lib/cookie.c-Curl_cookie_add": "struct Cookie *
Curl_cookie_add(struct Curl_easy *data,
                struct CookieInfo *c,
                bool httpheader, /* TRUE if HTTP header-style line */
                bool noexpire, /* if TRUE, skip remove_expired() */
                const char *lineptr,   /* first character of the line */
                const char *domain, /* default domain */
                const char *path,   /* full path used when this cookie is set,
                                       used to get default path for the cookie
                                       unless set */
                bool secure)  /* TRUE if connection is over secure origin */
{
  struct Cookie *clist;
  struct Cookie *co;
  struct Cookie *lastc = NULL;
  struct Cookie *replace_co = NULL;
  struct Cookie *replace_clist = NULL;
  time_t now = time(NULL);
  bool replace_old = FALSE;
  bool badcookie = FALSE; /* cookies are good by default. mmmmm yummy */
  size_t myhash;
  DEBUGASSERT(data);
  DEBUGASSERT(MAX_SET_COOKIE_AMOUNT <= 255); /* counter is an unsigned char */
  if(data->req.setcookies >= MAX_SET_COOKIE_AMOUNT)
    return NULL;
  /* First, alloc and init a new struct for it */
  co = calloc(1, sizeof(struct Cookie));
  if(!co)
    return NULL; /* bail out if we're this low on memory */
  if(httpheader) {
    /* This line was read off an HTTP-header */
    const char *ptr;
    size_t linelength = strlen(lineptr);
    if(linelength > MAX_COOKIE_LINE) {
      /* discard overly long lines at once */
      free(co);
      return NULL;
    }
    ptr = lineptr;
    do {
      size_t vlen;
      size_t nlen;
      while(*ptr && ISBLANK(*ptr))
        ptr++;
      /* we have a <name>=<value> pair or a stand-alone word here */
      nlen = strcspn(ptr, ";	

=");
      if(nlen) {
        bool done = FALSE;
        bool sep = FALSE;
        const char *namep = ptr;
        const char *valuep;
        ptr += nlen;
        /* trim trailing spaces and tabs after name */
        while(nlen && ISBLANK(namep[nlen - 1]))
          nlen--;
        if(*ptr == '=') {
          vlen = strcspn(++ptr, ";

");
          valuep = ptr;
          sep = TRUE;
          ptr = &valuep[vlen];
          /* Strip off trailing whitespace from the value */
          while(vlen && ISBLANK(valuep[vlen-1]))
            vlen--;
          /* Skip leading whitespace from the value */
          while(vlen && ISBLANK(*valuep)) {
            valuep++;
            vlen--;
          }
          /* Reject cookies with a TAB inside the value */
          if(memchr(valuep, '	', vlen)) {
            freecookie(co);
            infof(data, "cookie contains TAB, dropping");
            return NULL;
          }
        }
        else {
          valuep = NULL;
          vlen = 0;
        }
        /*
         * Check for too long individual name or contents, or too long
         * combination of name + contents. Chrome and Firefox support 4095 or
         * 4096 bytes combo
         */
        if(nlen >= (MAX_NAME-1) || vlen >= (MAX_NAME-1) ||
           ((nlen + vlen) > MAX_NAME)) {
          freecookie(co);
          infof(data, "oversized cookie dropped, name/val %zu + %zu bytes",
                nlen, vlen);
          return NULL;
        }
        /*
         * Check if we have a reserved prefix set before anything else, as we
         * otherwise have to test for the prefix in both the cookie name and
         * "the rest". Prefixes must start with '__' and end with a '-', so
         * only test for names where that can possibly be true.
         */
        if(nlen >= 7 && namep[0] == '_' && namep[1] == '_') {
          if(strncasecompare("__Secure-", namep, 9))
            co->prefix |= COOKIE_PREFIX__SECURE;
          else if(strncasecompare("__Host-", namep, 7))
            co->prefix |= COOKIE_PREFIX__HOST;
        }
        /*
         * Use strstore() below to properly deal with received cookie
         * headers that have the same string property set more than once,
         * and then we use the last one.
         */
        if(!co->name) {
          /* The very first name/value pair is the actual cookie name */
          if(!sep) {
            /* Bad name/value pair. */
            badcookie = TRUE;
            break;
          }
          strstore(&co->name, namep, nlen);
          strstore(&co->value, valuep, vlen);
          done = TRUE;
          if(!co->name || !co->value) {
            badcookie = TRUE;
            break;
          }
          if(invalid_octets(co->value) || invalid_octets(co->name)) {
            infof(data, "invalid octets in name/value, cookie dropped");
            badcookie = TRUE;
            break;
          }
        }
        else if(!vlen) {
          /*
           * this was a "<name>=" with no content, and we must allow
           * 'secure' and 'httponly' specified this weirdly
           */
          done = TRUE;
          /*
           * secure cookies are only allowed to be set when the connection is
           * using a secure protocol, or when the cookie is being set by
           * reading from file
           */
          if((nlen == 6) && strncasecompare("secure", namep, 6)) {
            if(secure || !c->running) {
              co->secure = TRUE;
            }
            else {
              badcookie = TRUE;
              break;
            }
          }
          else if((nlen == 8) && strncasecompare("httponly", namep, 8))
            co->httponly = TRUE;
          else if(sep)
            /* there was a '=' so we're not done parsing this field */
            done = FALSE;
        }
        if(done)
          ;
        else if((nlen == 4) && strncasecompare("path", namep, 4)) {
          strstore(&co->path, valuep, vlen);
          if(!co->path) {
            badcookie = TRUE; /* out of memory bad */
            break;
          }
          free(co->spath); /* if this is set again */
          co->spath = sanitize_cookie_path(co->path);
          if(!co->spath) {
            badcookie = TRUE; /* out of memory bad */
            break;
          }
        }
        else if((nlen == 6) &&
                strncasecompare("domain", namep, 6) && vlen) {
          bool is_ip;
          /*
           * Now, we make sure that our host is within the given domain, or
           * the given domain is not valid and thus cannot be set.
           */
          if('.' == valuep[0]) {
            valuep++; /* ignore preceding dot */
            vlen--;
          }
#ifndef USE_LIBPSL
          /*
           * Without PSL we don't know when the incoming cookie is set on a
           * TLD or otherwise "protected" suffix. To reduce risk, we require a
           * dot OR the exact host name being "localhost".
           */
          if(bad_domain(valuep, vlen))
            domain = ":";
#endif
          is_ip = Curl_host_is_ipnum(domain ? domain : valuep);
          if(!domain
             || (is_ip && !strncmp(valuep, domain, vlen) &&
                 (vlen == strlen(domain)))
             || (!is_ip && cookie_tailmatch(valuep, vlen, domain))) {
            strstore(&co->domain, valuep, vlen);
            if(!co->domain) {
              badcookie = TRUE;
              break;
            }
            if(!is_ip)
              co->tailmatch = TRUE; /* we always do that if the domain name was
                                       given */
          }
          else {
            /*
             * We did not get a tailmatch and then the attempted set domain is
             * not a domain to which the current host belongs. Mark as bad.
             */
            badcookie = TRUE;
            infof(data, "skipped cookie with bad tailmatch domain: %s",
                  valuep);
          }
        }
        else if((nlen == 7) && strncasecompare("version", namep, 7)) {
          /* just ignore */
        }
        else if((nlen == 7) && strncasecompare("max-age", namep, 7)) {
          /*
           * Defined in RFC2109:
           *
           * Optional.  The Max-Age attribute defines the lifetime of the
           * cookie, in seconds.  The delta-seconds value is a decimal non-
           * negative integer.  After delta-seconds seconds elapse, the
           * client should discard the cookie.  A value of zero means the
           * cookie should be discarded immediately.
           */
          CURLofft offt;
          const char *maxage = valuep;
          offt = curlx_strtoofft((*maxage == '"')?
                                 &maxage[1]:&maxage[0], NULL, 10,
                                 &co->expires);
          switch(offt) {
          case CURL_OFFT_FLOW:
            /* overflow, used max value */
            co->expires = CURL_OFF_T_MAX;
            break;
          case CURL_OFFT_INVAL:
            /* negative or otherwise bad, expire */
            co->expires = 1;
            break;
          case CURL_OFFT_OK:
            if(!co->expires)
              /* already expired */
              co->expires = 1;
            else if(CURL_OFF_T_MAX - now < co->expires)
              /* would overflow */
              co->expires = CURL_OFF_T_MAX;
            else
              co->expires += now;
            break;
          }
        }
        else if((nlen == 7) && strncasecompare("expires", namep, 7)) {
          char date[128];
          if(!co->expires && (vlen < sizeof(date))) {
            /* copy the date so that it can be null terminated */
            memcpy(date, valuep, vlen);
            date[vlen] = 0;
            /*
             * Let max-age have priority.
             *
             * If the date cannot get parsed for whatever reason, the cookie
             * will be treated as a session cookie
             */
            co->expires = Curl_getdate_capped(date);
            /*
             * Session cookies have expires set to 0 so if we get that back
             * from the date parser let's add a second to make it a
             * non-session cookie
             */
            if(co->expires == 0)
              co->expires = 1;
            else if(co->expires < 0)
              co->expires = 0;
          }
        }
        /*
         * Else, this is the second (or more) name we don't know about!
         */
      }
      else {
        /* this is an "illegal" <what>=<this> pair */
      }
      while(*ptr && ISBLANK(*ptr))
        ptr++;
      if(*ptr == ';')
        ptr++;
      else
        break;
    } while(1);
    if(!badcookie && !co->domain) {
      if(domain) {
        /* no domain was given in the header line, set the default */
        co->domain = strdup(domain);
        if(!co->domain)
          badcookie = TRUE;
      }
    }
    if(!badcookie && !co->path && path) {
      /*
       * No path was given in the header line, set the default.  Note that the
       * passed-in path to this function MAY have a '?' and following part that
       * MUST NOT be stored as part of the path.
       */
      char *queryp = strchr(path, '?');
      /*
       * queryp is where the interesting part of the path ends, so now we
       * want to the find the last
       */
      char *endslash;
      if(!queryp)
        endslash = strrchr(path, '/');
      else
        endslash = memrchr(path, '/', (queryp - path));
      if(endslash) {
        size_t pathlen = (endslash-path + 1); /* include end slash */
        co->path = malloc(pathlen + 1); /* one extra for the zero byte */
        if(co->path) {
          memcpy(co->path, path, pathlen);
          co->path[pathlen] = 0; /* null-terminate */
          co->spath = sanitize_cookie_path(co->path);
          if(!co->spath)
            badcookie = TRUE; /* out of memory bad */
        }
        else
          badcookie = TRUE;
      }
    }
    /*
     * If we didn't get a cookie name, or a bad one, the this is an illegal
     * line so bail out.
     */
    if(badcookie || !co->name) {
      freecookie(co);
      return NULL;
    }
    data->req.setcookies++;
  }
  else {
    /*
     * This line is NOT an HTTP header style line, we do offer support for
     * reading the odd netscape cookies-file format here
     */
    char *ptr;
    char *firstptr;
    char *tok_buf = NULL;
    int fields;
    /*
     * IE introduced HTTP-only cookies to prevent XSS attacks. Cookies marked
     * with httpOnly after the domain name are not accessible from javascripts,
     * but since curl does not operate at javascript level, we include them
     * anyway. In Firefox's cookie files, these lines are preceded with
     * #HttpOnly_ and then everything is as usual, so we skip 10 characters of
     * the line..
     */
    if(strncmp(lineptr, "#HttpOnly_", 10) == 0) {
      lineptr += 10;
      co->httponly = TRUE;
    }
    if(lineptr[0]=='#') {
      /* don't even try the comments */
      free(co);
      return NULL;
    }
    /* strip off the possible end-of-line characters */
    ptr = strchr(lineptr, '
');
    if(ptr)
      *ptr = 0; /* clear it */
    ptr = strchr(lineptr, '
');
    if(ptr)
      *ptr = 0; /* clear it */
    firstptr = strtok_r((char *)lineptr, "	", &tok_buf); /* tokenize on TAB */
    /*
     * Now loop through the fields and init the struct we already have
     * allocated
     */
    for(ptr = firstptr, fields = 0; ptr && !badcookie;
        ptr = strtok_r(NULL, "	", &tok_buf), fields++) {
      switch(fields) {
      case 0:
        if(ptr[0]=='.') /* skip preceding dots */
          ptr++;
        co->domain = strdup(ptr);
        if(!co->domain)
          badcookie = TRUE;
        break;
      case 1:
        /*
         * flag: A TRUE/FALSE value indicating if all machines within a given
         * domain can access the variable. Set TRUE when the cookie says
         * .domain.com and to false when the domain is complete www.domain.com
         */
        co->tailmatch = strcasecompare(ptr, "TRUE")?TRUE:FALSE;
        break;
      case 2:
        /* The file format allows the path field to remain not filled in */
        if(strcmp("TRUE", ptr) && strcmp("FALSE", ptr)) {
          /* only if the path doesn't look like a boolean option! */
          co->path = strdup(ptr);
          if(!co->path)
            badcookie = TRUE;
          else {
            co->spath = sanitize_cookie_path(co->path);
            if(!co->spath) {
              badcookie = TRUE; /* out of memory bad */
            }
          }
          break;
        }
        /* this doesn't look like a path, make one up! */
        co->path = strdup("/");
        if(!co->path)
          badcookie = TRUE;
        co->spath = strdup("/");
        if(!co->spath)
          badcookie = TRUE;
        fields++; /* add a field and fall down to secure */
        /* FALLTHROUGH */
      case 3:
        co->secure = FALSE;
        if(strcasecompare(ptr, "TRUE")) {
          if(secure || c->running)
            co->secure = TRUE;
          else
            badcookie = TRUE;
        }
        break;
      case 4:
        if(curlx_strtoofft(ptr, NULL, 10, &co->expires))
          badcookie = TRUE;
        break;
      case 5:
        co->name = strdup(ptr);
        if(!co->name)
          badcookie = TRUE;
        else {
          /* For Netscape file format cookies we check prefix on the name */
          if(strncasecompare("__Secure-", co->name, 9))
            co->prefix |= COOKIE_PREFIX__SECURE;
          else if(strncasecompare("__Host-", co->name, 7))
            co->prefix |= COOKIE_PREFIX__HOST;
        }
        break;
      case 6:
        co->value = strdup(ptr);
        if(!co->value)
          badcookie = TRUE;
        break;
      }
    }
    if(6 == fields) {
      /* we got a cookie with blank contents, fix it */
      co->value = strdup("");
      if(!co->value)
        badcookie = TRUE;
      else
        fields++;
    }
    if(!badcookie && (7 != fields))
      /* we did not find the sufficient number of fields */
      badcookie = TRUE;
    if(badcookie) {
      freecookie(co);
      return NULL;
    }
  }
  if(co->prefix & COOKIE_PREFIX__SECURE) {
    /* The __Secure- prefix only requires that the cookie be set secure */
    if(!co->secure) {
      freecookie(co);
      return NULL;
    }
  }
  if(co->prefix & COOKIE_PREFIX__HOST) {
    /*
     * The __Host- prefix requires the cookie to be secure, have a "/" path
     * and not have a domain set.
     */
    if(co->secure && co->path && strcmp(co->path, "/") == 0 && !co->tailmatch)
      ;
    else {
      freecookie(co);
      return NULL;
    }
  }
  if(!c->running &&    /* read from a file */
     c->newsession &&  /* clean session cookies */
     !co->expires) {   /* this is a session cookie since it doesn't expire! */
    freecookie(co);
    return NULL;
  }
  co->livecookie = c->running;
  co->creationtime = ++c->lastct;
  /*
   * Now we have parsed the incoming line, we must now check if this supersedes
   * an already existing cookie, which it may if the previous have the same
   * domain and path as this.
   */
  /* at first, remove expired cookies */
  if(!noexpire)
    remove_expired(c);
#ifdef USE_LIBPSL
  /*
   * Check if the domain is a Public Suffix and if yes, ignore the cookie. We
   * must also check that the data handle isn't NULL since the psl code will
   * dereference it.
   */
  if(data && (domain && co->domain && !Curl_host_is_ipnum(co->domain))) {
    const psl_ctx_t *psl = Curl_psl_use(data);
    int acceptable;

    if(psl) {
      acceptable = psl_is_cookie_domain_acceptable(psl, domain, co->domain);
      Curl_psl_release(data);
    }
    else
      acceptable = !bad_domain(domain, strlen(domain));

    if(!acceptable) {
      infof(data, "cookie '%s' dropped, domain '%s' must not "
                  "set cookies for '%s'", co->name, domain, co->domain);
      freecookie(co);
      return NULL;
    }
  }
#endif
  /* A non-secure cookie may not overlay an existing secure cookie. */
  myhash = cookiehash(co->domain);
  clist = c->cookies[myhash];
  while(clist) {
    if(strcasecompare(clist->name, co->name)) {
      /* the names are identical */
      bool matching_domains = FALSE;
      if(clist->domain && co->domain) {
        if(strcasecompare(clist->domain, co->domain))
          /* The domains are identical */
          matching_domains = TRUE;
      }
      else if(!clist->domain && !co->domain)
        matching_domains = TRUE;
      if(matching_domains && /* the domains were identical */
         clist->spath && co->spath && /* both have paths */
         clist->secure && !co->secure && !secure) {
        size_t cllen;
        const char *sep;
        /*
         * A non-secure cookie may not overlay an existing secure cookie.
         * For an existing cookie "a" with path "/login", refuse a new
         * cookie "a" with for example path "/login/en", while the path
         * "/loginhelper" is ok.
         */
        sep = strchr(clist->spath + 1, '/');
        if(sep)
          cllen = sep - clist->spath;
        else
          cllen = strlen(clist->spath);
        if(strncasecompare(clist->spath, co->spath, cllen)) {
          infof(data, "cookie '%s' for domain '%s' dropped, would "
                "overlay an existing cookie", co->name, co->domain);
          freecookie(co);
          return NULL;
        }
      }
    }
    if(!replace_co && strcasecompare(clist->name, co->name)) {
      /* the names are identical */
      if(clist->domain && co->domain) {
        if(strcasecompare(clist->domain, co->domain) &&
          (clist->tailmatch == co->tailmatch))
          /* The domains are identical */
          replace_old = TRUE;
      }
      else if(!clist->domain && !co->domain)
        replace_old = TRUE;
      if(replace_old) {
        /* the domains were identical */
        if(clist->spath && co->spath &&
           !strcasecompare(clist->spath, co->spath))
          replace_old = FALSE;
        else if(!clist->spath != !co->spath)
          replace_old = FALSE;
      }
      if(replace_old && !co->livecookie && clist->livecookie) {
        /*
         * Both cookies matched fine, except that the already present cookie is
         * "live", which means it was set from a header, while the new one was
         * read from a file and thus isn't "live". "live" cookies are preferred
         * so the new cookie is freed.
         */
        freecookie(co);
        return NULL;
      }
      if(replace_old) {
        replace_co = co;
        replace_clist = clist;
      }
    }
    lastc = clist;
    clist = clist->next;
  }
  if(replace_co) {
    co = replace_co;
    clist = replace_clist;
    co->next = clist->next; /* get the next-pointer first */
    /* when replacing, creationtime is kept from old */
    co->creationtime = clist->creationtime;
    /* then free all the old pointers */
    free(clist->name);
    free(clist->value);
    free(clist->domain);
    free(clist->path);
    free(clist->spath);
    *clist = *co;  /* then store all the new data */
    free(co);   /* free the newly allocated memory */
    co = clist;
  }
  if(c->running)
    /* Only show this when NOT reading the cookies from a file */
    infof(data, "%s cookie %s="%s" for domain %s, path %s, "
          "expire %" CURL_FORMAT_CURL_OFF_T,
          replace_old?"Replaced":"Added", co->name, co->value,
          co->domain, co->path, co->expires);
  if(!replace_old) {
    /* then make the last item point on this new one */
    if(lastc)
      lastc->next = co;
    else
      c->cookies[myhash] = co;
    c->numcookies++; /* one more cookie in the jar */
  }
  /*
   * Now that we've added a new cookie to the jar, update the expiration
   * tracker in case it is the next one to expire.
   */
  if(co->expires && (co->expires < c->next_expiration))
    c->next_expiration = co->expires;
  return co;
}