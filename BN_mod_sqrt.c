CURLcode Curl_http_header(struct Curl_easy *data, struct connectdata *conn,
                          char *headp)
{
  CURLcode result;
  struct SingleRequest *k = &data->req;
  /* Check for Content-Length: header lines to get size */
  if(!k->http_bodyless &&
     !data->set.ignorecl && checkprefix("Content-Length:", headp)) {
    curl_off_t contentlength;
    CURLofft offt = curlx_strtoofft(headp + strlen("Content-Length:"),
                                    NULL, 10, &contentlength);
    if(offt == CURL_OFFT_OK) {
      k->size = contentlength;
      k->maxdownload = k->size;
    }
    else if(offt == CURL_OFFT_FLOW) {
      /* out of range */
      if(data->set.max_filesize) {
        failf(data, "Maximum file size exceeded");
        return CURLE_FILESIZE_EXCEEDED;
      }
      streamclose(conn, "overflow content-length");
      infof(data, "Overflow Content-Length: value");
    }
    else {
      /* negative or just rubbish - bad HTTP */
      failf(data, "Invalid Content-Length: value");
      return CURLE_WEIRD_SERVER_REPLY;
    }
  }
  /* check for Content-Type: header lines to get the MIME-type */
  else if(checkprefix("Content-Type:", headp)) {
    char *contenttype = Curl_copy_header_value(headp);
    if(!contenttype)
      return CURLE_OUT_OF_MEMORY;
    if(!*contenttype)
      /* ignore empty data */
      free(contenttype);
    else {
      Curl_safefree(data->info.contenttype);
      data->info.contenttype = contenttype;
    }
  }
#ifndef CURL_DISABLE_PROXY
  else if((conn->httpversion == 10) &&
          conn->bits.httpproxy &&
          Curl_compareheader(headp,
                             STRCONST("Proxy-Connection:"),
                             STRCONST("keep-alive"))) {
    /*
     * When an HTTP/1.0 reply comes when using a proxy, the
     * 'Proxy-Connection: keep-alive' line tells us the
     * connection will be kept alive for our pleasure.
     * Default action for 1.0 is to close.
     */
    connkeep(conn, "Proxy-Connection keep-alive"); /* don't close */
    infof(data, "HTTP/1.0 proxy connection set to keep alive");
  }
  else if((conn->httpversion == 11) &&
          conn->bits.httpproxy &&
          Curl_compareheader(headp,
                             STRCONST("Proxy-Connection:"),
                             STRCONST("close"))) {
    /*
     * We get an HTTP/1.1 response from a proxy and it says it'll
     * close down after this transfer.
     */
    connclose(conn, "Proxy-Connection: asked to close after done");
    infof(data, "HTTP/1.1 proxy connection set close");
  }
#endif
  else if((conn->httpversion == 10) &&
          Curl_compareheader(headp,
                             STRCONST("Connection:"),
                             STRCONST("keep-alive"))) {
    /*
     * An HTTP/1.0 reply with the 'Connection: keep-alive' line
     * tells us the connection will be kept alive for our
     * pleasure.  Default action for 1.0 is to close.
     *
     * [RFC2068, section 19.7.1] */
    connkeep(conn, "Connection keep-alive");
    infof(data, "HTTP/1.0 connection set to keep alive");
  }
  else if(Curl_compareheader(headp,
                             STRCONST("Connection:"), STRCONST("close"))) {
    /*
     * [RFC 2616, section 8.1.2.1]
     * "Connection: close" is HTTP/1.1 language and means that
     * the connection will close when this request has been
     * served.
     */
    streamclose(conn, "Connection: close used");
  }
  else if(!k->http_bodyless && checkprefix("Transfer-Encoding:", headp)) {
    /* One or more encodings. We check for chunked and/or a compression
       algorithm. */
    /*
     * [RFC 2616, section 3.6.1] A 'chunked' transfer encoding
     * means that the server will send a series of "chunks". Each
     * chunk starts with line with info (including size of the
     * coming block) (terminated with CRLF), then a block of data
     * with the previously mentioned size. There can be any amount
     * of chunks, and a chunk-data set to zero signals the
     * end-of-chunks. */
    result = Curl_build_unencoding_stack(data,
                                         headp + strlen("Transfer-Encoding:"),
                                         TRUE);
    if(result)
      return result;
    if(!k->chunk) {
      /* if this isn't chunked, only close can signal the end of this transfer
         as Content-Length is said not to be trusted for transfer-encoding! */
      connclose(conn, "HTTP/1.1 transfer-encoding without chunks");
      k->ignore_cl = TRUE;
    }
  }
  else if(!k->http_bodyless && checkprefix("Content-Encoding:", headp) &&
          data->set.str[STRING_ENCODING]) {
    /*
     * Process Content-Encoding. Look for the values: identity,
     * gzip, deflate, compress, x-gzip and x-compress. x-gzip and
     * x-compress are the same as gzip and compress. (Sec 3.5 RFC
     * 2616). zlib cannot handle compress.  However, errors are
     * handled further down when the response body is processed
     */
    result = Curl_build_unencoding_stack(data,
                                         headp + strlen("Content-Encoding:"),
                                         FALSE);
    if(result)
      return result;
  }
  else if(checkprefix("Retry-After:", headp)) {
    /* Retry-After = HTTP-date / delay-seconds */
    curl_off_t retry_after = 0; /* zero for unknown or "now" */
    /* Try it as a decimal number, if it works it is not a date */
    (void)curlx_strtoofft(headp + strlen("Retry-After:"),
                          NULL, 10, &retry_after);
    if(!retry_after) {
      time_t date = Curl_getdate_capped(headp + strlen("Retry-After:"));
      if(-1 != date)
        /* convert date to number of seconds into the future */
        retry_after = date - time(NULL);
    }
    data->info.retry_after = retry_after; /* store it */
  }
  else if(!k->http_bodyless && checkprefix("Content-Range:", headp)) {
    /* Content-Range: bytes [num]-
       Content-Range: bytes: [num]-
       Content-Range: [num]-
       Content-Range: [asterisk]/[total]
       The second format was added since Sun's webserver
       JavaWebServer/1.1.1 obviously sends the header this way!
       The third added since some servers use that!
       The fourth means the requested range was unsatisfied.
    */
    char *ptr = headp + strlen("Content-Range:");
    /* Move forward until first digit or asterisk */
    while(*ptr && !ISDIGIT(*ptr) && *ptr != '*')
      ptr++;
    /* if it truly stopped on a digit */
    if(ISDIGIT(*ptr)) {
      if(!curlx_strtoofft(ptr, NULL, 10, &k->offset)) {
        if(data->state.resume_from == k->offset)
          /* we asked for a resume and we got it */
          k->content_range = TRUE;
      }
    }
    else
      data->state.resume_from = 0; /* get everything */
  }
#if !defined(CURL_DISABLE_COOKIES)
  else if(data->cookies && data->state.cookie_engine &&
          checkprefix("Set-Cookie:", headp)) {
    /* If there is a custom-set Host: name, use it here, or else use real peer
       host name. */
    const char *host = data->state.aptr.cookiehost?
      data->state.aptr.cookiehost:conn->host.name;
    const bool secure_context =
      conn->handler->protocol&(CURLPROTO_HTTPS|CURLPROTO_WSS) ||
      strcasecompare("localhost", host) ||
      !strcmp(host, "127.0.0.1") ||
      !strcmp(host, "[::1]") ? TRUE : FALSE;
    Curl_share_lock(data, CURL_LOCK_DATA_COOKIE,
                    CURL_LOCK_ACCESS_SINGLE);
    Curl_cookie_add(data, data->cookies, TRUE, FALSE,
                    headp + strlen("Set-Cookie:"), host,
                    data->state.up.path, secure_context);
    Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
  }
#endif
  else if(!k->http_bodyless && checkprefix("Last-Modified:", headp) &&
          (data->set.timecondition || data->set.get_filetime) ) {
    k->timeofdoc = Curl_getdate_capped(headp + strlen("Last-Modified:"));
    if(data->set.get_filetime)
      data->info.filetime = k->timeofdoc;
  }
  else if((checkprefix("WWW-Authenticate:", headp) &&
           (401 == k->httpcode)) ||
          (checkprefix("Proxy-authenticate:", headp) &&
           (407 == k->httpcode))) {
    bool proxy = (k->httpcode == 407) ? TRUE : FALSE;
    char *auth = Curl_copy_header_value(headp);
    if(!auth)
      return CURLE_OUT_OF_MEMORY;
    result = Curl_http_input_auth(data, proxy, auth);
    free(auth);
    if(result)
      return result;
  }
#ifdef USE_SPNEGO
  else if(checkprefix("Persistent-Auth:", headp)) {
    struct negotiatedata *negdata = &conn->negotiate;
    struct auth *authp = &data->state.authhost;
    if(authp->picked == CURLAUTH_NEGOTIATE) {
      char *persistentauth = Curl_copy_header_value(headp);
      if(!persistentauth)
        return CURLE_OUT_OF_MEMORY;
      negdata->noauthpersist = checkprefix("false", persistentauth)?
        TRUE:FALSE;
      negdata->havenoauthpersist = TRUE;
      infof(data, "Negotiate: noauthpersist -> %d, header part: %s",
            negdata->noauthpersist, persistentauth);
      free(persistentauth);
    }
  }
#endif
  else if((k->httpcode >= 300 && k->httpcode < 400) &&
          checkprefix("Location:", headp) &&
          !data->req.location) {
    /* this is the URL that the server advises us to use instead */
    char *location = Curl_copy_header_value(headp);
    if(!location)
      return CURLE_OUT_OF_MEMORY;
    if(!*location)
      /* ignore empty data */
      free(location);
    else {
      data->req.location = location;
      if(data->set.http_follow_location) {
        DEBUGASSERT(!data->req.newurl);
        data->req.newurl = strdup(data->req.location); /* clone */
        if(!data->req.newurl)
          return CURLE_OUT_OF_MEMORY;
        /* some cases of POST and PUT etc needs to rewind the data
           stream at this point */
        result = http_perhapsrewind(data, conn);
        if(result)
          return result;
        /* mark the next request as a followed location: */
        data->state.this_is_a_follow = TRUE;
      }
    }
  }
#ifndef CURL_DISABLE_HSTS
  /* If enabled, the header is incoming and this is over HTTPS */
  else if(data->hsts && checkprefix("Strict-Transport-Security:", headp) &&
          ((conn->handler->flags & PROTOPT_SSL) ||
#ifdef CURLDEBUG
           /* allow debug builds to circumvent the HTTPS restriction */
           getenv("CURL_HSTS_HTTP")
#else
           0
#endif
            )) {
    CURLcode check =
      Curl_hsts_parse(data->hsts, data->state.up.hostname,
                      headp + strlen("Strict-Transport-Security:"));
    if(check)
      infof(data, "Illegal STS header skipped");
#ifdef DEBUGBUILD
    else
      infof(data, "Parsed STS header fine (%zu entries)",
            data->hsts->list.size);
#endif
  }
#endif
#ifndef CURL_DISABLE_ALTSVC
  /* If enabled, the header is incoming and this is over HTTPS */
  else if(data->asi && checkprefix("Alt-Svc:", headp) &&
          ((conn->handler->flags & PROTOPT_SSL) ||
#ifdef CURLDEBUG
           /* allow debug builds to circumvent the HTTPS restriction */
           getenv("CURL_ALTSVC_HTTP")
#else
           0
#endif
            )) {
    /* the ALPN of the current request */
    enum alpnid id = (conn->httpversion == 20) ? ALPN_h2 : ALPN_h1;
    result = Curl_altsvc_parse(data, data->asi,
                               headp + strlen("Alt-Svc:"),
                               id, conn->host.name,
                               curlx_uitous((unsigned int)conn->remote_port));
    if(result)
      return result;
  }
#endif
  else if(conn->handler->protocol & CURLPROTO_RTSP) {
    result = Curl_rtsp_parseheader(data, headp);
    if(result)
      return result;
  }
  return CURLE_OK;
}