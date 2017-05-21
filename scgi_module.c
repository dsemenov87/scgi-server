#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>

#define MAXEVENTS 64

#define FNDELAY O_NDELAY

/*
 * If a browser connects, but doesn't do anything, how long until kicking them off
 * (See also the next comment below)
 */
#define SCGI_KICK_IDLE_AFTER_X_SECS 60

/*
 * How many times, per second, will your main project be checking for new connections?
 * (Rather than keep track of the exact time a client is idle, rather we keep track of
 *  the number of times we've checked for updates and found none.  When the client has
 *  been idle for SCGI_KICK_IDLE_AFTER_X_SECS * SCGI_PULSE_PER_SEC consecutive checks,
 *  they will be booted.  SCGI_PULSES_PER_SEC is not used anywhere else.  Thus, it is
 *  not terribly important that it be completely precise, a ballpark estimate is good
 *  enough.
 */
#define SCGI_PULSES_PER_SEC 10

/*
 * Different states of a client.
 */
#define SCGI_SOCKSTATE_READING_REQUEST 0
#define SCGI_SOCKSTATE_WRITING_RESPONSE 1

/*
 * How many bytes of memory to initially allocate for I/O buffers when a client connects.
 * (These will automatically be grown when/if the client sends a bigger amount of input or
 * SCGI C Library responds with a bigger amount of output)
 */
#define SCGI_INITIAL_OUTBUF_SIZE 16384
#define SCGI_INITIAL_INBUF_SIZE 16384

/*
 * Upper limits on the number of bytes for I/O buffers.  If they send more data than this,
 * or compel us to send a bigger response, SCGI C Library assumes it is an attack and kills
 * the connection.
 */
#define SCGI_MAX_INBUF_SIZE 131072
#define SCGI_MAX_OUTBUF_SIZE 524288

/*
 * If multiple clients simultaneously attempt to connect, how many connections should SCGI C Library
 * accept at once?  Any additional simultaneous connections beyond this limit will have to wait
 * their turn.
 */
#define SCGI_LISTEN_BACKLOG_PER_PORT 32

/*
 * Macros for handling generic doubly-linked lists
 */
#define SCGI_LINK(link, first, last, next, prev) \
do                                          \
{                                           \
   if ( !(first) )                          \
   {                                        \
      (first) = (link);                     \
      (last) = (link);                      \
   }                                        \
   else                                     \
      (last)->next = (link);                \
   (link)->next = NULL;                     \
   if ((first) == (link))                   \
      (link)->prev = NULL;                  \
   else                                     \
      (link)->prev = (last);                \
   (last) = (link);                         \
} while(0)

#define SCGI_UNLINK(link, first, last, next, prev)   \
do                                              \
{                                               \
   if ( !(link)->prev )                         \
   {                                            \
      (first) = (link)->next;                   \
      if ((first))                              \
         (first)->prev = NULL;                  \
   }                                            \
   else                                         \
   {                                            \
      (link)->prev->next = (link)->next;        \
   }                                            \
   if ( !(link)->next )                         \
   {                                            \
      (last) = (link)->prev;                    \
      if((last))                                \
         (last)->next = NULL; \
   }                                            \
   else                                         \
   {                                            \
      (link)->next->prev = (link)->prev;        \
   }                                            \
} while (0)

/*
 * Memory allocation macro
 */
#define SCGI_CREATE(result, type, number)				\
do									\
{									\
   if (!((result) = (type *) calloc ((number), sizeof(type))))		\
   {									\
      fprintf(stderr, "scgilib: Out of RAM! Emergency shutdown.\n" );	\
      abort();								\
   }									\
} while(0)

/*
 * Different parts of the SCGI protocol
 */
typedef enum
{
  SCGI_PARSE_HEADLENGTH,
  SCGI_PARSE_HEADNAME,
  SCGI_PARSE_HEADVAL,
  SCGI_PARSE_BODY
} scgi_parse_state_t;

/*
 * Different HTTP request types
 * (right now the SCGI C Library is mainly only built to handle GET and HEAD)
 */
typedef enum
{
  SCGI_METHOD_UNSPECIFIED,
  SCGI_METHOD_UNKNOWN,
  SCGI_METHOD_GET,
  SCGI_METHOD_POST,
  SCGI_METHOD_HEAD
} scgi_method_t;

/*
 * Data structure for a header in the SCGI protocol
 */
typedef struct scgi_header_s
{
  struct scgi_header_s *next;
  struct scgi_header_s *prev;
  char *name;			// name of the header
  char *value;		// value of the header
} scgi_header_t;

/*
 * Data structure for a successfully parsed SCGI request.
 * This is what any project using the SCGI C Library will primarily interact with.
 */
typedef struct scgi_request_s
{
  struct scgi_request_s *next;
  struct scgi_request_s *prev;
  struct scgi_request_s *next_unrecved;
  struct scgi_request_s *prev_unrecved;
  //scgi_conn_t *descriptor;	    // info about the connection
  scgi_header_t *first_header;	// doubly-linked list of request headers
  scgi_header_t *last_header;
  char *body;			// request body
  int scgi_content_length;	// length of the request body
  char scgi_scgiheader;		// whether or not the request included the "SCGI" header
  int *dead;			// pointer to an int which SCGI C Library can use to specify whether a connection is dead (see documentation for details)
  int request_method;		// type of request (SCGI_METHOD_GET, SCGI_METHOD_POST, SCGI_METHOD_HEAD, or SCGI_METHOD_UNKNOWN)
  char *http_host;		// which host name are they connecting to (in principle, with this, you can have one program serve multiple domain names)
  /*
   * The remaining fields are some individual headers that might be sent
   */
  char *query_string;
  char *request_uri;
  char *http_cache_control;
  char *raw_http_cookie;
  char *http_connection;
  char *http_accept_encoding;
  char *http_accept_language;
  char *http_accept_charset;
  char *http_accept;
  char *user_agent;
  char *remote_addr;		// Client's IP address
  char *server_port;
  char *server_addr;
  char *server_protocol;
} scgi_request_t;

/*
 * Info about a connection
 */
typedef struct scgi_conn_s
{
  //struct scgi_conn_s *next;
  //struct scgi_conn_s *prev;
  //scgi_port *port;		//which port are they connected to
  //scgi_request_t *req;		//info about the request they are sending
  //int sock;			//which socket they're bound to
  char *buf;			//input buffer for the data they're sending us
  int bufsize;			//how much space we've allocated so far for the data they're sending us
  int buflen;			//how much data they've sent us so far
  char *outbuf;			//output buffer for data we're going to send them
  int outbufsize;		//how much space we've allocated for outbuf so far
  int outbuflen;		//how long outbuf has become so far
  int idle;			//how many times we checked the connection for new data and found it idle
  int state;			//which state is this connection in
  char *writehead;		//pointer to the end of the data currently stored in outbuf
} scgi_conn_t;

typedef struct scgi_parser_ctx_s {
  int parsed_chars;
  char *string_starts;
  int true_header_length;
  int true_request_length;
  int parser_state;
} scgi_parser_ctx_t;

typedef struct scgi_ctx_s {
  scgi_conn_t *conn;
  scgi_request_t *req;
  scgi_parser_ctx_t *parser_ctx;
} scgi_ctx_t;

typedef struct scgi_epoll_ctx_s {
  int sfd;
  int efd;
  struct epoll_event event;
  struct epoll_event *events;
} scgi_epoll_ctx_t;

static scgi_conn_t
__scgi_create_conn()
{
  scgi_conn_t *conn;
  SCGI_CREATE( conn, scgi_conn_t, 1 );
  // conn->next = NULL;
  // conn->prev = NULL;
  // conn->port = port;
  conn->sock = caller;
  conn->idle = 0;
  conn->state = SCGI_SOCKSTATE_READING_REQUEST;
  conn->writehead = NULL;
  conn->parsed_chars = 0;
  conn->string_starts = NULL;
  conn->parser_state = SCGI_PARSE_HEADLENGTH;

  SCGI_CREATE( conn->buf, char, SCGI_INITIAL_INBUF_SIZE + 1 );
  conn->bufsize = SCGI_INITIAL_INBUF_SIZE;
  conn->buflen = 0;
  *conn->buf = '\0';

  SCGI_CREATE( conn->outbuf, char, SCGI_INITIAL_OUTBUF_SIZE + 1 );
  conn->outbufsize = SCGI_INITIAL_OUTBUF_SIZE;
  conn->outbuflen = 0;
  *conn->outbuf = '\0';

  return conn;
}

static scgi_request_t
__scgi_create_request(scgi_conn_t *conn)
{
  scgi_request_t *req;
  SCGI_CREATE( req, scgi_request_t, 1 );
  req->next = NULL;
  req->prev = NULL;
  req->next_unrecved = NULL;
  req->prev_unrecved = NULL;
  req->descriptor = conn;

  req->first_header = NULL;
  req->last_header = NULL;
  req->body = NULL;
  req->scgi_content_length = -1;
  req->scgi_scgiheader = 0;
  req->dead = NULL;

  req->request_method = SCGI_METHOD_UNSPECIFIED;
  req->http_host = NULL;
  req->query_string = NULL;
  req->request_uri = NULL;
  req->http_cache_control = NULL;
  req->raw_http_cookie = NULL;
  req->http_connection = NULL;
  req->http_accept_encoding = NULL;
  req->http_accept_language = NULL;
  req->http_accept_charset = NULL;
  req->http_accept = NULL;
  req->user_agent = NULL;
  req->remote_addr = NULL;
  req->server_port = NULL;
  req->server_addr = NULL;
  req->server_protocol = NULL;

  // SCGI_LINK( req, first_scgi_req, last_scgi_req, next, prev );

  // SCGI_LINK( d, p->first_scgi_desc, p->last_scgi_desc, next, prev );

  return req;
}

static int
__make_socket_non_blocking (int sfd)
{
  int flags, s;

  flags = fcntl (sfd, F_GETFL, 0);
  if (flags == -1)
  {
    perror ("fcntl");
    return -1;
  }

  flags |= O_NONBLOCK;
  s = fcntl (sfd, F_SETFL, flags);
  if (s == -1)
  {
    perror ("fcntl");
    return -1;
  }

  return 0;
}

static int
__scgi_create_listener (char *port)
{
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int s, sfd;

  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_UNSPEC;     /* Return IPv4 and IPv6 choices */
  hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */
  hints.ai_flags = AI_PASSIVE;     /* All interfaces */

  s = getaddrinfo (NULL, port, &hints, &result);
  if (s != 0)
  {
    fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (s));
    return -1;
  }

  for (rp = result; rp != NULL; rp = rp->ai_next)
  {
    sfd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sfd == -1)
      continue;

    s = bind (sfd, rp->ai_addr, rp->ai_addrlen);
    if (s == 0)
    {
      /* We managed to bind successfully! */
      s = __make_socket_non_blocking (sfd);
      if (s == -1)
        abort ();
      
      break;
    }

    close (sfd);
  }

  if (rp == NULL)
  {
    fprintf (stderr, "Could not bind\n");
    return -1;
  }

  freeaddrinfo (result);

  return sfd;
}

static void
__scgi_handle_incoming_conn(scgi_epoll_ctx_t *ctx)
{
  while (1)
  {
    struct sockaddr in_addr;
    socklen_t in_len;
    int infd;
    char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

    in_len = sizeof in_addr;
    infd = accept (ctx->sfd, &in_addr, &in_len);
    if (infd == -1)
    {
      if ((errno == EAGAIN) ||
          (errno == EWOULDBLOCK))
      {
        /* We have processed all incoming
         * connections.
         */
        break;
      }
      else
      {
        perror ("accept");
        break;
      }
    }

    s = getnameinfo (&in_addr, in_len,
                      hbuf, sizeof hbuf,
                      sbuf, sizeof sbuf,
                      NI_NUMERICHOST | NI_NUMERICSERV);
    if (s == 0)
    {
      printf("Accepted connection on descriptor %d "
              "(host=%s, port=%s)\n", infd, hbuf, sbuf);
    }

    /* Make the incoming socket non-blocking and add it to the
     * list of fds to monitor.
     */
    s = __make_socket_non_blocking (infd);
    if (s == -1)
      abort ();

    /*
     * The connection has been made. Let's commit it to RAM.
     */
    scgi_ctx_t *scgi_ctx;
    SCGI_CREATE( scgi_ctx, scgi_ctx_t, 1 );
    scgi_ctx->conn = __scgi_create_conn();
    scgi_ctx->req = __scgi_create_request();

    ctx->event.data.fd = infd;
    ctx->event.data->ptr = (void*)scgi_ctx;
    ctx->event.events = EPOLLIN | EPOLLET;
    s = epoll_ctl (ctx->efd, EPOLL_CTL_ADD, infd, &ctx->event);
    if (s == -1)
    {
      perror ("epoll_ctl");
      abort ();
    }
  }
}

/*
 * Delete an SCGI request from memory
 */
static void
__free_scgi_request( scgi_request_t *r )
{
  scgi_header_t *h, *h_next;
  scgi_request_t *ptr;

  if ( !r )
    return;

  /*
   * The request is now dead.  If the programmer (you) supplied the location of an integer,
   * we will use it to signal the request's deadness, so you can avoid trying to do anything
   * with the no-longer-existent connection.
   */
  if ( r->dead )
  {
    *r->dead = 1;
  }

  //SCGI_UNLINK( r, first_scgi_req, last_scgi_req, next, prev );

  // for ( ptr = first_scgi_unrecved_req; ptr; ptr = ptr->next_unrecved )
  // {
  //   if ( ptr == r )
  //   {
  //     SCGI_UNLINK( r, first_scgi_unrecved_req, last_scgi_unrecved_req, next_unrecved, prev_unrecved );
  //     break;
  //   }
  // }

  for ( h = r->first_header; h; h = h_next )
  {
    h_next = h->next;
    free( h->name );
    free( h->value );
    free( h );
  }

  if ( r->body )
    free( r->body );

  free( r );
}

/*
 * Kick a connection offline and delete it from memory
 */
static void
__scgi_kill_socket( int sock, scgi_ctx_t *ctx )
{
  scgi_conn_t *conn;
  conn = ctx->conn;
  free( conn->buf );
  free( conn->outbuf );
  free( conn );

  __free_scgi_request( ctx->req );
  close( sock );
}

/*
 * If more I/O space is needed than allocated, allocate more (up to a limit)
 * Returns 0 (and kills the connection) if the specified limit has been reached
 */
static int
__scgi_resize_buffer( scgi_conn_t *conn, char **buf )
{
  int max, *size;
  char *tmp;

  if ( *buf == conn->buf )
  {
    max = SCGI_MAX_INBUF_SIZE;
    size = &conn->bufsize;
  }
  else
  {
    max = SCGI_MAX_OUTBUF_SIZE;
    size = &conn->outbufsize;
  }

  *size *= 2;
  if ( *size >= max )
  {
    __scgi_kill_socket(conn);
    return 0;
  }

  /*
   * Special treatment rather than the usual malloc macro, just because I thought this
   * particular function might have a bigger risk of sucking up too much RAM and so it
   * would be better to handle it directly rather than use a generic macro
   */
  tmp = (char *) calloc((*size)+1, sizeof(char) );
  if ( !tmp )
  {
    scgi_deal_with_socket_out_of_ram(d);
    return 0;
  }

  sprintf( tmp, "%s", *buf );
  free( *buf );
  *buf = tmp;
  return 1;
}

/*
 * Parse input according to the SCGI protocol.
 * Due to the asynchronous nature of SCGI, we may or may not have received
 * the full input (it might be that more is still on its way), and there's no
 * way to tell without parsing, so the parser must be capable of stopping,
 * remembering where it left off, and indicating as much (which it does via
 * states in the descriptor structure).
 */
static void
__scgi_parse_input( scgi_ctx_t *ctx )
{
  scgi_parser_ctx_t *parser_ctx;
  parser_ctx = ctx->parser_ctx;

  scgi_conn_t *conn;
  conn = ctx->conn;

  char *parser = &conn->buf[parser_ctx->parsed_chars], *end, *headername, *headerval;
  int len, total_req_length, headernamelen;

  /*
   * Everything has already been parsed, so do nothing until new input arrives.
   */
  if ( d->parsed_chars == d->buflen )
    return;

  /*
   * If they are not following the SCGI protocol, we have no choice but to hang up on them.
   * The very first character must not be 0 or : or it would be an invalid netstring
   * (well, technically it could be the empty netstring, but that's invalid SCGI as well,
   * if it's at the very start of the transmission)
   */
  if ( d->parsed_chars == 0 && (*d->buf == '0' || *d->buf == ':') )
  {
    scgi_kill_socket(d);
    return;
  }

  end = &d->buf[d->buflen];


scgi_parse_input_label:

  /*
   * How to proceed depends where we left off last time (if ever) we were parsing this input.
   */
  switch( d->parser_state )
  {
    case SCGI_PARSE_HEADLENGTH:   // Oh yeah, we were in the middle of reading the length of their headers.  (This is the default state)
      while ( parser < end )
      {
        d->parsed_chars++;

        /*
         * The end of the header length is indicated by :, we've successfully read the header's length.
         */
        if ( *parser == ':' )
        {
          d->parser_state = SCGI_PARSE_HEADNAME; // the next task is to read the first header's name.
          /*
           * Replace the colon with an end-of-string so we can use strtoul to read the number.
           */
          *parser = '\0';
          d->true_header_length = strtoul(d->buf,NULL,10) + strlen(d->buf) + 2;
          *parser = ':'; // undo the end-of-string change we made above
          parser++;
          d->string_starts = parser;
          goto scgi_parse_input_label;
        }
        if ( *parser < '0' || *parser > '9' )
        {
          /*
           * If they're trying to indicate a non-number length, they're making a mockery of the SCGI protocol,
           * kick them right out.
           */
          scgi_kill_socket(d);
          return;
        }
        parser++;
      }
      break;

    case SCGI_PARSE_HEADNAME: // Oh yeah, we were in the middle of reading a header's name.
      while ( parser < end )
      {
        d->parsed_chars++;

        if ( d->parsed_chars == d->true_header_length )
        {
          /*
           * If we're supposedly at the end of the headers (based on the length they transmitted),
           * but the headers don't end with "\0,", then it's invalid SCGI.  Been nice knowing you...
           */
          if ( *parser != ',' || parser[-1] != '\0' )
          {
            scgi_kill_socket(d);
            return;
          }

          /*
           * They didn't send an "SCGI" header with value 1.
           * Are they using some different protocol?  Whatever, not our problem.  Door's that way.
           */
          if ( !d->req->scgi_scgiheader )
          {
            scgi_kill_socket(d);
            return;
          }

          /*
           * If their headers indicated that no body is coming, then we're done.
           * Put the parsed request in the list of requests which have been parsed but not yet
           * communicated to you (the programmer of whatever program is including scgilib).
           */
          if ( d->req->scgi_content_length == 0 )
          {
            SCGI_CREATE( d->req->body, char, 2 );

            *d->req->body = '\0';

            SCGI_LINK( d->req, first_scgi_unrecved_req, last_scgi_unrecved_req, next_unrecved, prev_unrecved );
            return;
          }
          len = strtoul(d->req->first_header->value,NULL,10);
          d->true_request_length = len + d->true_header_length;
          parser++;
          d->string_starts = parser;

          /*
           * Next task is to start reading the body after the headers
           */
          d->parser_state = SCGI_PARSE_BODY;

          goto scgi_parse_input_label;
        }

        /*
         * A '\0' indicates the end of the header's name.
         */
        if ( *parser == '\0' )
        {
          /*
           * Of course, a header with the empty string as its name is forbidden and no such
           * nonsense will be tolerated.
           */
          if ( parser == d->string_starts )
          {
            scgi_kill_socket(d);
            return;
          }

          /*
           * Having a header's name, our next task is to parse its value.
           */
          d->parser_state = SCGI_PARSE_HEADVAL;
          parser++;
          goto scgi_parse_input_label;
        }
        parser++;
      }
      break;

    case SCGI_PARSE_HEADVAL:
      while ( parser < end )
      {
        d->parsed_chars++;

        /*
         * We expected a header value, and instead we reached the end of the headers (according to
         * the header length they specified)?!  Nope.jpg
         */
        if ( d->parsed_chars == d->true_header_length )
        {
          scgi_kill_socket(d);
          return;
        }

        /*
         * We've successfully read the value of the current header.
         * Create a structure for this header and store it.
         */
        if ( *parser == '\0' )
        {
          headernamelen = strlen(d->string_starts);
          SCGI_CREATE( headername, char, headernamelen+1 );
          sprintf( headername, "%s", d->string_starts );
          SCGI_CREATE( headerval, char, strlen(&d->string_starts[headernamelen+1])+1 );
          sprintf( headerval, "%s", &d->string_starts[headernamelen+1] );
          if ( !scgi_add_header( d, headername, headerval ) )
            return;
          /*
           * Next task: parse the next header's name.
           */
          d->parser_state = SCGI_PARSE_HEADNAME;
          parser++;
          d->string_starts = parser;
          goto scgi_parse_input_label;
        }
        parser++;
      }
      break;

    case SCGI_PARSE_BODY:
      total_req_length = d->true_header_length + d->req->scgi_content_length;

      while ( parser < end )
      {
        d->parsed_chars++;

        if ( d->parsed_chars == total_req_length )
        {
          parser[1] = '\0';
          SCGI_CREATE( d->req->body, char, strlen(d->string_starts)+1 );
          sprintf( d->req->body, "%s", d->string_starts );
          SCGI_LINK( d->req, first_scgi_unrecved_req, last_scgi_unrecved_req, next_unrecved, prev_unrecved );

          return;
        }
        parser++;
      }
      break;
  }

  return;
}

/*
 * A socket is ready for us to read (continue reading?) its input!  So read it.
 */
static void
__scgi_listen_to_request( int fd, scgi_ctx_t *ctx )
{
  scgi_conn_t *conn;
  conn = ctx->conn;
  int start = conn->buflen, readsize;

  /*
   * If their buffer is sufficiently near full and there's still more to be read,
   * then increase the buffer.  If they're spamming with an enormous request,
   * the connection will be terminated in resize_buffer.
   */
  if ( start >= conn->bufsize - 5 )
  {
    if ( !__scgi_resize_buffer( conn, &conn->buf ) )
      return;
  }

  /*
   * Read as much as we can.  Can't wait around, since there may be other connections to attend to,
   * so just read as much as possible and make a note of how much that was (the socket is non-blocking
   * so this won't cause us to hang even if the incoming message would otherwise take time to recv)
   */
  readsize = recv( fd, conn->buf + start, conn->bufsize - 5 - start, 0 );

  /*
   * There's new input, successfully read and stored in memory!  Let's parse it and figure out what
   * the heck they're asking for!  (Who knows whether we've got their full transmission or whether
   * there's still more in the pipeline-- we'll let the parser figure that out based on the SCGI
   * protocol)
   */
  if ( readsize > 0 )
  {
    conn->buflen += readsize;
    __scgi_parse_input( fd );
    return;
  }

  /*
   * Something unexpected happened.  This is the wild untamed internet, so kill the connection first and
   * ask questions later.
   */
  if ( readsize == 0 || errno != EWOULDBLOCK )
  {
    __scgi_kill_socket( fd, ctx );
    return;
  }
}

static int
__scgi_handle_request( int i, scgi_epoll_ctx_t *ctx)
{
  int done;
  epoll_event *ev;
  ev = ctx->events[i];

  scgi_ctx_t *scgi_ctx;
  scgi_ctx = (scgi_ctx_t *)ev.data->ptr;

  int fd = ev.data.fd;
  scgi_conn_t *conn = scgi_ctx->conn;
  int idle = ++conn->idle;

  while (1)
  {
    ssize_t count;
    char buf[512];
    count = read (fd, buf, sizeof buf);
    if (count == -1)
    {
      /* If errno == EAGAIN, that means we have read all
       * data. So go back to the main loop.
       */
      if (errno != EAGAIN)
      {
        perror ("read");
        __scgi_kill_socket( fd, scgi_ctx );
        done = 1;
      }
      return done;
    }
    else if (count == 0)
    {
      /* End of file. The remote has closed the
       * connection.
       */
      done = 1;
      __scgi_kill_socket( fd, scgi_ctx );
      return done;
    }

    /*
     * Handle remote I/O, provided the connections are ready for it
     */
    if ( conn->state == SCGI_SOCKSTATE_READING_REQUEST
    &&   ev.events & EPOLLIN )
    {
      conn->idle = 0;
      __scgi_listen_to_request( d );
    }
    else
    if ( conn->state == SCGI_SOCKSTATE_WRITING_RESPONSE
    &&   conn->outbuflen > 0
    &&   ev.events & EPOLLOUT )
    {
      conn->idle = 0;
      __scgi_flush_response( d );
    }
    else
    {
      /*
       * Kick connections out if they're idle too long
       */
      if (idle > SCGI_KICK_IDLE_AFTER_X_SECS * SCGI_PULSES_PER_SEC)
      {
        __scgi_kill_socket( fd, scgi_ctx );
        return 1;
      }
    }
    // s = write (1, buf, count);
    // if (-1 == s)
    // {
    //   perror ("write");
    //   abort ();
    // }
  }
}

static int
__scgi_handle_socket(int i, scgi_epoll_ctx_t *ctx)
{
  if ((ctx->events[i].events & EPOLLERR) ||
      (ctx->events[i].events & EPOLLHUP))
  {
    /* An error has occured on this fd, or the socket is not
     * ready for reading (why were we notified then?)
     */
    fprintf (stderr, "epoll error\n");
    close (ctx->events[i].data.fd);
    continue;
  }
  else if (ctx->sfd == ctx->events[i].data.fd)
  {
    /* We have a notification on the listening socket, which
     * means one or more incoming connections.
     */
    __scgi_handle_incoming_conn(ctx);
    continue;
  }
  else
  {
    /* We have data on the fd waiting to be handle.
     * We must read whatever data is available
     * completely, as we are running in edge-triggered mode
     * and won't get a notification again for the same
     * data.
     */
    if (__scgi_handle_request(i, ctx))
    {
      printf ("Closed connection on descriptor %d\n",
              ctx->events[i].data.fd);

      /* Closing the descriptor will make epoll remove it
       * from the set of descriptors which are monitored.
       */
      close (ctx->events[i].data.fd);
    }
  }
}

scgi_epoll_ctx_t *
scgi_epoll_ctx_init (char *port)
{
  int s;
  scgi_epoll_ctx_t *ctx
  
  ctx->sfd = __scgi_create_listener (port);
  if (ctx->sfd == -1)
    abort ();

  s = listen (ctx->sfd, SOMAXCONN);
  if (s == -1)
  {
    perror ("listen");
    abort ();
  }

  ctx->efd = epoll_create1 (0);
  if (ctx->efd == -1)
  {
    perror ("epoll_create");
    abort ();
  }

  ctx->event.data.fd = ctx->sfd;
  ctx->event.events = EPOLLIN | EPOLLET;
  s = epoll_ctl (ctx->efd, EPOLL_CTL_ADD, ctx->sfd, &ctx->event);
  if (s == -1)
  {
    perror ("epoll_ctl");
    abort ();
  }

  /* Buffer where events are returned */
  ctx->events = calloc (MAXEVENTS, sizeof (epoll_event));

  return ctx;
}

int
scgi_iterate_sockets(scgi_epoll_ctx_t *ctx)
{
  int n, i;
  n = epoll_wait (ctx->efd, ctx->events, MAXEVENTS, -1);
  for (i = 0; i < n; i++)
  {
    __scgi_handle_socket(int i, scgi_epoll_ctx_t *ctx);
  }
}

int
main (int argc, char *argv[])
{
  int s;
  scgi_epoll_ctx_t *ctx = scgi_epoll_ctx_init(argv[1]);

  /* The event loop */
  while (1)
  {
    scgi_iterate_sockets(scgi_epoll_ctx_t *ctx);
  }
  
  free (events);
  close (sfd);

  return EXIT_SUCCESS;
}