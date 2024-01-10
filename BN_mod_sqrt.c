src/rfc3315.c-dhcp6_no_relay": " static int dhcp6_no_relay(struct state *state, int msg_type, void *inbuff, size_t sz, int is_unicast, time_t now)
 {
   void *opt;
   int i, o, o1, start_opts;
   struct dhcp_opt *opt_cfg;
   struct dhcp_netid *tagif;
   struct dhcp_config *config = NULL;
   struct dhcp_netid known_id, iface_id, v6_id;
   unsigned char *outmsgtypep;
   struct dhcp_vendor *vendor;
   struct dhcp_context *context_tmp;
   struct dhcp_mac *mac_opt;
   unsigned int ignore = 0;
 
   state->packet_options = inbuff + 4;
   state->end = inbuff + sz;
   state->clid = NULL;
   state->clid_len = 0;
   state->lease_allocate = 0;
   state->context_tags = NULL;
   state->domain = NULL;
   state->send_domain = NULL;
   state->hostname_auth = 0;
   state->hostname = NULL;
   state->client_hostname = NULL;
   state->fqdn_flags = 0x01; /* default to send if we receive no FQDN option */
 
   /* set tag with name == interface */
   iface_id.net = state->iface_name;
   iface_id.next = state->tags;
   state->tags = &iface_id; 
 
   /* set tag "dhcpv6" */
   v6_id.net = "dhcpv6";
   v6_id.next = state->tags;
   state->tags = &v6_id;
 
   /* copy over transaction-id, and save pointer to message type */
   if (!(outmsgtypep = put_opt6(inbuff, 4)))
     return 0;
   start_opts = save_counter(-1);
   state->xid = outmsgtypep[3] | outmsgtypep[2] << 8 | outmsgtypep[1] << 16;
    
   /* We're going to be linking tags from all context we use. 
      mark them as unused so we don't link one twice and break the list */
   for (context_tmp = state->context; context_tmp; context_tmp = context_tmp->current)
     {
       context_tmp->netid.next = &context_tmp->netid;
 
       if (option_bool(OPT_LOG_OPTS))
         {
            inet_ntop(AF_INET6, &context_tmp->start6, daemon->dhcp_buff, ADDRSTRLEN); 
            inet_ntop(AF_INET6, &context_tmp->end6, daemon->dhcp_buff2, ADDRSTRLEN); 
            if (context_tmp->flags & (CONTEXT_STATIC))
              my_syslog(MS_DHCP | LOG_INFO, _("%u available DHCPv6 subnet: %s/%d"),
                        state->xid, daemon->dhcp_buff, context_tmp->prefix);
            else
              my_syslog(MS_DHCP | LOG_INFO, _("%u available DHCP range: %s -- %s"), 
                        state->xid, daemon->dhcp_buff, daemon->dhcp_buff2);
         }
     }
 
   if ((opt = opt6_find(state->packet_options, state->end, OPTION6_CLIENT_ID, 1)))
     {
       state->clid = opt6_ptr(opt, 0);
       state->clid_len = opt6_len(opt);
       o = new_opt6(OPTION6_CLIENT_ID);
       put_opt6(state->clid, state->clid_len);
       end_opt6(o);
     }
   else if (msg_type != DHCP6IREQ)
     return 0;
 
   /* server-id must match except for SOLICIT, CONFIRM and REBIND messages */
   if (msg_type != DHCP6SOLICIT && msg_type != DHCP6CONFIRM && msg_type != DHCP6IREQ && msg_type != DHCP6REBIND &&
       (!(opt = opt6_find(state->packet_options, state->end, OPTION6_SERVER_ID, 1)) ||
        opt6_len(opt) != daemon->duid_len ||
        memcmp(opt6_ptr(opt, 0), daemon->duid, daemon->duid_len) != 0))
     return 0;
   
   o = new_opt6(OPTION6_SERVER_ID);
   put_opt6(daemon->duid, daemon->duid_len);
   end_opt6(o);
 
   if (is_unicast &&
       (msg_type == DHCP6REQUEST || msg_type == DHCP6RENEW || msg_type == DHCP6RELEASE || msg_type == DHCP6DECLINE))
     
     {  
       *outmsgtypep = DHCP6REPLY;
       o1 = new_opt6(OPTION6_STATUS_CODE);
       put_opt6_short(DHCP6USEMULTI);
       put_opt6_string("Use multicast");
       end_opt6(o1);
       return 1;
     }
 
   /* match vendor and user class options */
   for (vendor = daemon->dhcp_vendors; vendor; vendor = vendor->next)
     {
       int mopt;
       
       if (vendor->match_type == MATCH_VENDOR)
         mopt = OPTION6_VENDOR_CLASS;
       else if (vendor->match_type == MATCH_USER)
         mopt = OPTION6_USER_CLASS; 
       else
         continue;
 
       if ((opt = opt6_find(state->packet_options, state->end, mopt, 2)))
         {
           void *enc_opt, *enc_end = opt6_ptr(opt, opt6_len(opt));
           int offset = 0;
           
           if (mopt == OPTION6_VENDOR_CLASS)
             {
               if (opt6_len(opt) < 4)
                 continue;
               
               if (vendor->enterprise != opt6_uint(opt, 0, 4))
                 continue;
             
               offset = 4;
             }
  
           /* Note that format if user/vendor classes is different to DHCP options - no option types. */
           for (enc_opt = opt6_ptr(opt, offset); enc_opt; enc_opt = opt6_user_vendor_next(enc_opt, enc_end))
             for (i = 0; i <= (opt6_user_vendor_len(enc_opt) - vendor->len); i++)
               if (memcmp(vendor->data, opt6_user_vendor_ptr(enc_opt, i), vendor->len) == 0)
                 {
                   vendor->netid.next = state->tags;
                   state->tags = &vendor->netid;
                   break;
                 }
         }
     }
 
   if (option_bool(OPT_LOG_OPTS) && (opt = opt6_find(state->packet_options, state->end, OPTION6_VENDOR_CLASS, 4)))
     my_syslog(MS_DHCP | LOG_INFO, _("%u vendor class: %u"), state->xid, opt6_uint(opt, 0, 4));
   
   /* dhcp-match. If we have hex-and-wildcards, look for a left-anchored match.
      Otherwise assume the option is an array, and look for a matching element. 
      If no data given, existence of the option is enough. This code handles 
      V-I opts too. */
   for (opt_cfg = daemon->dhcp_match6; opt_cfg; opt_cfg = opt_cfg->next)
     {
       int match = 0;
       
       if (opt_cfg->flags & DHOPT_RFC3925)
         {
           for (opt = opt6_find(state->packet_options, state->end, OPTION6_VENDOR_OPTS, 4);
                opt;
                opt = opt6_find(opt6_next(opt, state->end), state->end, OPTION6_VENDOR_OPTS, 4))
             {
               void *vopt;
               void *vend = opt6_ptr(opt, opt6_len(opt));
               
               for (vopt = opt6_find(opt6_ptr(opt, 4), vend, opt_cfg->opt, 0);
                    vopt;
                    vopt = opt6_find(opt6_next(vopt, vend), vend, opt_cfg->opt, 0))
                 if ((match = match_bytes(opt_cfg, opt6_ptr(vopt, 0), opt6_len(vopt))))
                   break;
             }
           if (match)
             break;
         }
       else
         {
           if (!(opt = opt6_find(state->packet_options, state->end, opt_cfg->opt, 1)))
             continue;
           
           match = match_bytes(opt_cfg, opt6_ptr(opt, 0), opt6_len(opt));
         } 
   
       if (match)
         {
           opt_cfg->netid->next = state->tags;
           state->tags = opt_cfg->netid;
         }
     }
 
   if (state->mac_len != 0)
     {
       if (option_bool(OPT_LOG_OPTS))
         {
           print_mac(daemon->dhcp_buff, state->mac, state->mac_len);
           my_syslog(MS_DHCP | LOG_INFO, _("%u client MAC address: %s"), state->xid, daemon->dhcp_buff);
         }
 
       for (mac_opt = daemon->dhcp_macs; mac_opt; mac_opt = mac_opt->next)
         if ((unsigned)mac_opt->hwaddr_len == state->mac_len &&
             ((unsigned)mac_opt->hwaddr_type == state->mac_type || mac_opt->hwaddr_type == 0) &&
             memcmp_masked(mac_opt->hwaddr, state->mac, state->mac_len, mac_opt->mask))
           {
             mac_opt->netid.next = state->tags;
             state->tags = &mac_opt->netid;
           }
     }
   
   if ((opt = opt6_find(state->packet_options, state->end, OPTION6_FQDN, 1)))
     {
       /* RFC4704 refers */
        int len = opt6_len(opt) - 1;
        
        state->fqdn_flags = opt6_uint(opt, 0, 1);
        
        /* Always force update, since the client has no way to do it itself. */
        if (!option_bool(OPT_FQDN_UPDATE) && !(state->fqdn_flags & 0x01))
          state->fqdn_flags |= 0x03;
  
        state->fqdn_flags &= ~0x04;
 
        if (len != 0 && len < 255)
          {
            unsigned char *pp, *op = opt6_ptr(opt, 1);
            char *pq = daemon->dhcp_buff;
            
            pp = op;
            while (*op != 0 && ((op + (*op)) - pp) < len)
              {
                memcpy(pq, op+1, *op);
                pq += *op;
                op += (*op)+1;
                *(pq++) = '.';
              }
            
            if (pq != daemon->dhcp_buff)
              pq--;
            *pq = 0;
            
            if (legal_hostname(daemon->dhcp_buff))
              {
                struct dhcp_match_name *m;
                size_t nl = strlen(daemon->dhcp_buff);
                
                state->client_hostname = daemon->dhcp_buff;
                
                if (option_bool(OPT_LOG_OPTS))
                  my_syslog(MS_DHCP | LOG_INFO, _("%u client provides name: %s"), state->xid, state->client_hostname);
                
                for (m = daemon->dhcp_name_match; m; m = m->next)
                  {
                    size_t ml = strlen(m->name);
                    char save = 0;
                    
                    if (nl < ml)
                      continue;
                    if (nl > ml)
                      {
                        save = state->client_hostname[ml];
                        state->client_hostname[ml] = 0;
                      }
                    
                    if (hostname_isequal(state->client_hostname, m->name) &&
                        (save == 0 || m->wildcard))
                      {
                        m->netid->next = state->tags;
                        state->tags = m->netid;
                      }
                    
                    if (save != 0)
                      state->client_hostname[ml] = save;
                  }
              }
          }
     }    
   
   if (state->clid &&
       (config = find_config(daemon->dhcp_conf, state->context, state->clid, state->clid_len,
                             state->mac, state->mac_len, state->mac_type, NULL, run_tag_if(state->tags))) &&
       have_config(config, CONFIG_NAME))
     {
       state->hostname = config->hostname;
       state->domain = config->domain;
       state->hostname_auth = 1;
     }
   else if (state->client_hostname)
     {
       state->domain = strip_hostname(state->client_hostname);
       
       if (strlen(state->client_hostname) != 0)
         {
           state->hostname = state->client_hostname;
           
           if (!config)
             {
               /* Search again now we have a hostname. 
                  Only accept configs without CLID here, (it won't match)
                  to avoid impersonation by name. */
               struct dhcp_config *new = find_config(daemon->dhcp_conf, state->context, NULL, 0, NULL, 0, 0, state->hostname, run_tag_if(state->tags));
               if (new && !have_config(new, CONFIG_CLID) && !new->hwaddr)
                 config = new;
             }
         }
     }
 
   if (config)
     {
       struct dhcp_netid_list *list;
       
       for (list = config->netid; list; list = list->next)
         {
           list->list->next = state->tags;
           state->tags = list->list;
         }
 
       /* set "known" tag for known hosts */
       known_id.net = "known";
       known_id.next = state->tags;
       state->tags = &known_id;
 
       if (have_config(config, CONFIG_DISABLE))
         ignore = 1;
     }
   else if (state->clid &&
            find_config(daemon->dhcp_conf, NULL, state->clid, state->clid_len,
                        state->mac, state->mac_len, state->mac_type, NULL, run_tag_if(state->tags)))
     {
       known_id.net = "known-othernet";
       known_id.next = state->tags;
       state->tags = &known_id;
     }
   
   tagif = run_tag_if(state->tags);
   
   /* if all the netids in the ignore list are present, ignore this client */
   if (daemon->dhcp_ignore)
     {
       struct dhcp_netid_list *id_list;
      
       for (id_list = daemon->dhcp_ignore; id_list; id_list = id_list->next)
         if (match_netid(id_list->list, tagif, 0))
           ignore = 1;
     }
   
   /* if all the netids in the ignore_name list are present, ignore client-supplied name */
   if (!state->hostname_auth)
     {
        struct dhcp_netid_list *id_list;
        
        for (id_list = daemon->dhcp_ignore_names; id_list; id_list = id_list->next)
          if ((!id_list->list) || match_netid(id_list->list, tagif, 0))
            break;
        if (id_list)
          state->hostname = NULL;
     }
   
 
   switch (msg_type)
     {
     default:
       return 0;
       
       
     case DHCP6SOLICIT:
       {
         int address_assigned = 0;
         /* tags without all prefix-class tags */
         struct dhcp_netid *solicit_tags;
         struct dhcp_context *c;
         
         *outmsgtypep = DHCP6ADVERTISE;
         
         if (opt6_find(state->packet_options, state->end, OPTION6_RAPID_COMMIT, 0))
           {
             *outmsgtypep = DHCP6REPLY;
             state->lease_allocate = 1;
             o = new_opt6(OPTION6_RAPID_COMMIT);
             end_opt6(o);
           }
         
         log6_quiet(state, "DHCPSOLICIT", NULL, ignore ? _("ignored") : NULL);
 
       request_no_address:
         solicit_tags = tagif;
         
         if (ignore)
           return 0;
         
         /* reset USED bits in leases */
         lease6_reset();
 
         /* Can use configured address max once per prefix */
         for (c = state->context; c; c = c->current)
           c->flags &= ~CONTEXT_CONF_USED;
 
         for (opt = state->packet_options; opt; opt = opt6_next(opt, state->end))
           {   
             void *ia_option, *ia_end;
             unsigned int min_time = 0xffffffff;
             int t1cntr;
             int ia_counter;
             /* set unless we're sending a particular prefix-class, when we
                want only dhcp-ranges with the correct tags set and not those without any tags. */
             int plain_range = 1;
             u32 lease_time;
             struct dhcp_lease *ltmp;
             struct in6_addr req_addr, addr;
             
             if (!check_ia(state, opt, &ia_end, &ia_option))
               continue;
             
             /* reset USED bits in contexts - one address per prefix per IAID */
             for (c = state->context; c; c = c->current)
               c->flags &= ~CONTEXT_USED;
 
             o = build_ia(state, &t1cntr);
             if (address_assigned)
                 address_assigned = 2;
 
             for (ia_counter = 0; ia_option; ia_counter++, ia_option = opt6_find(opt6_next(ia_option, ia_end), ia_end, OPTION6_IAADDR, 24))
               {
                 /* worry about alignment here. */
                 memcpy(&req_addr, opt6_ptr(ia_option, 0), IN6ADDRSZ);
                                 
                 if ((c = address6_valid(state->context, &req_addr, solicit_tags, plain_range)))
                   {
                     lease_time = c->lease_time;
                     /* If the client asks for an address on the same network as a configured address, 
                        offer the configured address instead, to make moving to newly-configured
                        addresses automatic. */
                     if (!(c->flags & CONTEXT_CONF_USED) && config_valid(config, c, &addr, state, now))
                       {
                         req_addr = addr;
                         mark_config_used(c, &addr);
                         if (have_config(config, CONFIG_TIME))
                           lease_time = config->lease_time;
                       }
                     else if (!(c = address6_available(state->context, &req_addr, solicit_tags, plain_range)))
                       continue; /* not an address we're allowed */
                     else if (!check_address(state, &req_addr))
                       continue; /* address leased elsewhere */
                     
                     /* add address to output packet */
                     add_address(state, c, lease_time, ia_option, &min_time, &req_addr, now);
                     mark_context_used(state, &req_addr);
                     get_context_tag(state, c);
                     address_assigned = 1;
                   }
               }
             
             /* Suggest configured address(es) */
             for (c = state->context; c; c = c->current) 
               if (!(c->flags & CONTEXT_CONF_USED) &&
                   match_netid(c->filter, solicit_tags, plain_range) &&
                   config_valid(config, c, &addr, state, now))
                 {
                   mark_config_used(state->context, &addr);
                   if (have_config(config, CONFIG_TIME))
                     lease_time = config->lease_time;
                   else
                     lease_time = c->lease_time;
 
                   /* add address to output packet */
                   add_address(state, c, lease_time, NULL, &min_time, &addr, now);
                   mark_context_used(state, &addr);
                   get_context_tag(state, c);
                   address_assigned = 1;
                 }
             
             /* return addresses for existing leases */
             ltmp = NULL;
             while ((ltmp = lease6_find_by_client(ltmp, state->ia_type == OPTION6_IA_NA ? LEASE_NA : LEASE_TA, state->clid, state->clid_len, state->iaid)))
               {
                 req_addr = ltmp->addr6;
                 if ((c = address6_available(state->context, &req_addr, solicit_tags, plain_range)))
                   {
                     add_address(state, c, c->lease_time, NULL, &min_time, &req_addr, now);
                     mark_context_used(state, &req_addr);
                     get_context_tag(state, c);
                     address_assigned = 1;
                   }
               }
                            
             /* Return addresses for all valid contexts which don't yet have one */
             while ((c = address6_allocate(state->context, state->clid, state->clid_len, state->ia_type == OPTION6_IA_TA,
                                           state->iaid, ia_counter, solicit_tags, plain_range, &addr)))
               {
                 add_address(state, c, c->lease_time, NULL, &min_time, &addr, now);
                 mark_context_used(state, &addr);
                 get_context_tag(state, c);
                 address_assigned = 1;
               }
             
             if (address_assigned != 1)
               {
                 /* If the server will not assign any addresses to any IAs in a
                    subsequent Request from the client, the server MUST send an Advertise
                    message to the client that doesn't include any IA options. */
                 if (!state->lease_allocate)
                   {
                     save_counter(o);
                     continue;
                   }
                 
                 /* If the server cannot assign any addresses to an IA in the message
                    from the client, the server MUST include the IA in the Reply message
                    with no addresses in the IA and a Status Code option in the IA
                    containing status code NoAddrsAvail. */
                 o1 = new_opt6(OPTION6_STATUS_CODE);
                 put_opt6_short(DHCP6NOADDRS);
                 put_opt6_string(_("address unavailable"));
                 end_opt6(o1);
               }
             
             end_ia(t1cntr, min_time, 0);
             end_opt6(o);        
           }
 
         if (address_assigned) 
           {
             o1 = new_opt6(OPTION6_STATUS_CODE);
             put_opt6_short(DHCP6SUCCESS);
             put_opt6_string(_("success"));
             end_opt6(o1);
             
             /* If --dhcp-authoritative is set, we can tell client not to wait for
                other possible servers */
             o = new_opt6(OPTION6_PREFERENCE);
             put_opt6_char(option_bool(OPT_AUTHORITATIVE) ? 255 : 0);
             end_opt6(o);
             tagif = add_options(state, 0);
           }
         else
           { 
             /* no address, return error */
             o1 = new_opt6(OPTION6_STATUS_CODE);
             put_opt6_short(DHCP6NOADDRS);
             put_opt6_string(_("no addresses available"));
             end_opt6(o1);
 
             /* Some clients will ask repeatedly when we're not giving
                out addresses because we're in stateless mode. Avoid spamming
                the log in that case. */
             for (c = state->context; c; c = c->current)
               if (!(c->flags & CONTEXT_RA_STATELESS))
                 {
                   log6_packet(state, state->lease_allocate ? "DHCPREPLY" : "DHCPADVERTISE", NULL, _("no addresses available"));
                   break;
                 }
           }
 
         break;
       }
       
     case DHCP6REQUEST:
       {
         int address_assigned = 0;
         int start = save_counter(-1);
 
         /* set reply message type */
         *outmsgtypep = DHCP6REPLY;
         state->lease_allocate = 1;
 
         log6_quiet(state, "DHCPREQUEST", NULL, ignore ? _("ignored") : NULL);
         
         if (ignore)
           return 0;
         
         for (opt = state->packet_options; opt; opt = opt6_next(opt, state->end))
           {   
             void *ia_option, *ia_end;
             unsigned int min_time = 0xffffffff;
             int t1cntr;
             
              if (!check_ia(state, opt, &ia_end, &ia_option))
                continue;
 
              if (!ia_option)
                {
                  /* If we get a request with an IA_*A without addresses, treat it exactly like
                     a SOLICT with rapid commit set. */
                  save_counter(start);
                  goto request_no_address; 
                }
 
             o = build_ia(state, &t1cntr);
               
             for (; ia_option; ia_option = opt6_find(opt6_next(ia_option, ia_end), ia_end, OPTION6_IAADDR, 24))
               {
                 struct in6_addr req_addr;
                 struct dhcp_context *dynamic, *c;
                 unsigned int lease_time;
                 int config_ok = 0;
 
                 /* align. */
                 memcpy(&req_addr, opt6_ptr(ia_option, 0), IN6ADDRSZ);
                 
                 if ((c = address6_valid(state->context, &req_addr, tagif, 1)))
                   config_ok = (config_implies(config, c, &req_addr) != NULL);
                 
                 if ((dynamic = address6_available(state->context, &req_addr, tagif, 1)) || c)
                   {
                     if (!dynamic && !config_ok)
                       {
                         /* Static range, not configured. */
                         o1 = new_opt6(OPTION6_STATUS_CODE);
                         put_opt6_short(DHCP6NOADDRS);
                         put_opt6_string(_("address unavailable"));
                         end_opt6(o1);
                       }
                     else if (!check_address(state, &req_addr))
                       {
                         /* Address leased to another DUID/IAID */
                         o1 = new_opt6(OPTION6_STATUS_CODE);
                         put_opt6_short(DHCP6UNSPEC);
                         put_opt6_string(_("address in use"));
                         end_opt6(o1);
                       } 
                     else 
                       {
                         if (!dynamic)
                           dynamic = c;
 
                         lease_time = dynamic->lease_time;
                         
                         if (config_ok && have_config(config, CONFIG_TIME))
                           lease_time = config->lease_time;
 
                         add_address(state, dynamic, lease_time, ia_option, &min_time, &req_addr, now);
                         get_context_tag(state, dynamic);
                         address_assigned = 1;
                       }
                   }
                 else 
                   {
                     /* requested address not on the correct link */
                     o1 = new_opt6(OPTION6_STATUS_CODE);
                     put_opt6_short(DHCP6NOTONLINK);
                     put_opt6_string(_("not on link"));
                     end_opt6(o1);
                   }
               }
          
             end_ia(t1cntr, min_time, 0);
             end_opt6(o);        
           }
 
         if (address_assigned) 
           {
             o1 = new_opt6(OPTION6_STATUS_CODE);
             put_opt6_short(DHCP6SUCCESS);
             put_opt6_string(_("success"));
             end_opt6(o1);
           }
         else
           { 
             /* no address, return error */
             o1 = new_opt6(OPTION6_STATUS_CODE);
             put_opt6_short(DHCP6NOADDRS);
             put_opt6_string(_("no addresses available"));
             end_opt6(o1);
             log6_packet(state, "DHCPREPLY", NULL, _("no addresses available"));
           }
 
         tagif = add_options(state, 0);
         break;
       }
       
   
     case DHCP6RENEW:
     case DHCP6REBIND:
       {
         int address_assigned = 0;
 
         /* set reply message type */
         *outmsgtypep = DHCP6REPLY;
         
         log6_quiet(state, msg_type == DHCP6RENEW ? "DHCPRENEW" : "DHCPREBIND", NULL, NULL);
 
         for (opt = state->packet_options; opt; opt = opt6_next(opt, state->end))
           {
             void *ia_option, *ia_end;
             unsigned int min_time = 0xffffffff;
             int t1cntr, iacntr;
             
             if (!check_ia(state, opt, &ia_end, &ia_option))
               continue;
             
             o = build_ia(state, &t1cntr);
             iacntr = save_counter(-1); 
             
             for (; ia_option; ia_option = opt6_find(opt6_next(ia_option, ia_end), ia_end, OPTION6_IAADDR, 24))
               {
                 struct dhcp_lease *lease = NULL;
                 struct in6_addr req_addr;
                 unsigned int preferred_time =  opt6_uint(ia_option, 16, 4);
                 unsigned int valid_time =  opt6_uint(ia_option, 20, 4);
                 char *message = NULL;
                 struct dhcp_context *this_context;
 
                 memcpy(&req_addr, opt6_ptr(ia_option, 0), IN6ADDRSZ); 
                 
                 if (!(lease = lease6_find(state->clid, state->clid_len,
                                           state->ia_type == OPTION6_IA_NA ? LEASE_NA : LEASE_TA, 
                                           state->iaid, &req_addr)))
                   {
                     if (msg_type == DHCP6REBIND)
                       {
                         /* When rebinding, we can create a lease if it doesn't exist. */
                         lease = lease6_allocate(&req_addr, state->ia_type == OPTION6_IA_NA ? LEASE_NA : LEASE_TA);
                         if (lease)
                           lease_set_iaid(lease, state->iaid);
                         else
                           break;
                       }
                     else
                       {
                         /* If the server cannot find a client entry for the IA the server
                            returns the IA containing no addresses with a Status Code option set
                            to NoBinding in the Reply message. */
                         save_counter(iacntr);
                         t1cntr = 0;
                         
                         log6_packet(state, "DHCPREPLY", &req_addr, _("lease not found"));
                         
                         o1 = new_opt6(OPTION6_STATUS_CODE);
                         put_opt6_short(DHCP6NOBINDING);
                         put_opt6_string(_("no binding found"));
                         end_opt6(o1);
                         
                         preferred_time = valid_time = 0;
                         break;
                       }
                   }
                 
                 if ((this_context = address6_available(state->context, &req_addr, tagif, 1)) ||
                     (this_context = address6_valid(state->context, &req_addr, tagif, 1)))
                   {
                     unsigned int lease_time;
 
                     get_context_tag(state, this_context);
                     
                     if (config_implies(config, this_context, &req_addr) && have_config(config, CONFIG_TIME))
                       lease_time = config->lease_time;
                     else 
                       lease_time = this_context->lease_time;
                     
                     calculate_times(this_context, &min_time, &valid_time, &preferred_time, lease_time); 
                     
                     lease_set_expires(lease, valid_time, now);
                     /* Update MAC record in case it's new information. */
                     if (state->mac_len != 0)
                       lease_set_hwaddr(lease, state->mac, state->clid, state->mac_len, state->mac_type, state->clid_len, now, 0);
                     if (state->ia_type == OPTION6_IA_NA && state->hostname)
                       {
                         char *addr_domain = get_domain6(&req_addr);
                         if (!state->send_domain)
                           state->send_domain = addr_domain;
                         lease_set_hostname(lease, state->hostname, state->hostname_auth, addr_domain, state->domain); 
                         message = state->hostname;
                       }
                     
                     
                     if (preferred_time == 0)
                       message = _("deprecated");
 
                     address_assigned = 1;
                   }
                 else
                   {
                     preferred_time = valid_time = 0;
                     message = _("address invalid");
                   } 
 
                 if (message && (message != state->hostname))
                   log6_packet(state, "DHCPREPLY", &req_addr, message);  
                 else
                   log6_quiet(state, "DHCPREPLY", &req_addr, message);
         
                 o1 =  new_opt6(OPTION6_IAADDR);
                 put_opt6(&req_addr, sizeof(req_addr));
                 put_opt6_long(preferred_time);
                 put_opt6_long(valid_time);
                 end_opt6(o1);
               }
             
             end_ia(t1cntr, min_time, 1);
             end_opt6(o);
           }
 
         if (!address_assigned && msg_type == DHCP6REBIND)
           { 
             /* can't create lease for any address, return error */
             o1 = new_opt6(OPTION6_STATUS_CODE);
             put_opt6_short(DHCP6NOADDRS);
             put_opt6_string(_("no addresses available"));
             end_opt6(o1);
           }
         
         tagif = add_options(state, 0);
         break;
       }
       
     case DHCP6CONFIRM:
       {
         int good_addr = 0;
 
         /* set reply message type */
         *outmsgtypep = DHCP6REPLY;
         
         log6_quiet(state, "DHCPCONFIRM", NULL, NULL);
         
         for (opt = state->packet_options; opt; opt = opt6_next(opt, state->end))
           {
             void *ia_option, *ia_end;
             
             for (check_ia(state, opt, &ia_end, &ia_option);
                  ia_option;
                  ia_option = opt6_find(opt6_next(ia_option, ia_end), ia_end, OPTION6_IAADDR, 24))
               {
                 struct in6_addr req_addr;
 
                 /* alignment */
                 memcpy(&req_addr, opt6_ptr(ia_option, 0), IN6ADDRSZ);
                 
                 if (!address6_valid(state->context, &req_addr, tagif, 1))
                   {
                     o1 = new_opt6(OPTION6_STATUS_CODE);
                     put_opt6_short(DHCP6NOTONLINK);
                     put_opt6_string(_("confirm failed"));
                     end_opt6(o1);
                     log6_quiet(state, "DHCPREPLY", &req_addr, _("confirm failed"));
                     return 1;
                   }
 
                 good_addr = 1;
                 log6_quiet(state, "DHCPREPLY", &req_addr, state->hostname);
               }
           }      
         
         /* No addresses, no reply: RFC 3315 18.2.2 */
         if (!good_addr)
           return 0;
 
         o1 = new_opt6(OPTION6_STATUS_CODE);
         put_opt6_short(DHCP6SUCCESS );
         put_opt6_string(_("all addresses still on link"));
         end_opt6(o1);
         break;
     }
       
     case DHCP6IREQ:
       {
         /* We can't discriminate contexts based on address, as we don't know it.
            If there is only one possible context, we can use its tags */
         if (state->context && state->context->netid.net && !state->context->current)
           {
             state->context->netid.next = NULL;
             state->context_tags =  &state->context->netid;
           }
 
         /* Similarly, we can't determine domain from address, but if the FQDN is
            given in --dhcp-host, we can use that, and failing that we can use the 
            unqualified configured domain, if any. */
         if (state->hostname_auth)
           state->send_domain = state->domain;
         else
           state->send_domain = get_domain6(NULL);
 
         log6_quiet(state, "DHCPINFORMATION-REQUEST", NULL, ignore ? _("ignored") : state->hostname);
         if (ignore)
           return 0;
         *outmsgtypep = DHCP6REPLY;
         tagif = add_options(state, 1);
         break;
       }
       
       
     case DHCP6RELEASE:
       {
         /* set reply message type */
         *outmsgtypep = DHCP6REPLY;
 
         log6_quiet(state, "DHCPRELEASE", NULL, NULL);
 
         for (opt = state->packet_options; opt; opt = opt6_next(opt, state->end))
           {
             void *ia_option, *ia_end;
             int made_ia = 0;
                     
             for (check_ia(state, opt, &ia_end, &ia_option);
                  ia_option;
                  ia_option = opt6_find(opt6_next(ia_option, ia_end), ia_end, OPTION6_IAADDR, 24)) 
               {
                 struct dhcp_lease *lease;
                 struct in6_addr addr;
 
                 /* align */
                 memcpy(&addr, opt6_ptr(ia_option, 0), IN6ADDRSZ);
                 if ((lease = lease6_find(state->clid, state->clid_len, state->ia_type == OPTION6_IA_NA ? LEASE_NA : LEASE_TA,
                                          state->iaid, &addr)))
                   lease_prune(lease, now);
                 else
                   {
                     if (!made_ia)
                       {
                         o = new_opt6(state->ia_type);
                         put_opt6_long(state->iaid);
                         if (state->ia_type == OPTION6_IA_NA)
                           {
                             put_opt6_long(0);
                             put_opt6_long(0); 
                           }
                         made_ia = 1;
                       }
                     
                     o1 = new_opt6(OPTION6_IAADDR);
                     put_opt6(&addr, IN6ADDRSZ);
                     put_opt6_long(0);
                     put_opt6_long(0);
                     end_opt6(o1);
                   }
               }
             
             if (made_ia)
               {
                 o1 = new_opt6(OPTION6_STATUS_CODE);
                 put_opt6_short(DHCP6NOBINDING);
                 put_opt6_string(_("no binding found"));
                 end_opt6(o1);
                 
                 end_opt6(o);
               }
           }
         
         o1 = new_opt6(OPTION6_STATUS_CODE);
         put_opt6_short(DHCP6SUCCESS);
         put_opt6_string(_("release received"));
         end_opt6(o1);
         
         break;
       }
 
     case DHCP6DECLINE:
       {
         /* set reply message type */
         *outmsgtypep = DHCP6REPLY;
         
         log6_quiet(state, "DHCPDECLINE", NULL, NULL);
 
         for (opt = state->packet_options; opt; opt = opt6_next(opt, state->end))
           {
             void *ia_option, *ia_end;
             int made_ia = 0;
                     
             for (check_ia(state, opt, &ia_end, &ia_option);
                  ia_option;
                  ia_option = opt6_find(opt6_next(ia_option, ia_end), ia_end, OPTION6_IAADDR, 24)) 
               {
                 struct dhcp_lease *lease;
                 struct in6_addr addr;
                 struct addrlist *addr_list;
                 
                 /* align */
                 memcpy(&addr, opt6_ptr(ia_option, 0), IN6ADDRSZ);
 
                 if ((addr_list = config_implies(config, state->context, &addr)))
                   {
                     prettyprint_time(daemon->dhcp_buff3, DECLINE_BACKOFF);
                     inet_ntop(AF_INET6, &addr, daemon->addrbuff, ADDRSTRLEN);
                     my_syslog(MS_DHCP | LOG_WARNING, _("disabling DHCP static address %s for %s"), 
                               daemon->addrbuff, daemon->dhcp_buff3);
                     addr_list->flags |= ADDRLIST_DECLINED;
                     addr_list->decline_time = now;
                   }
                 else
                   /* make sure this host gets a different address next time. */
                   for (context_tmp = state->context; context_tmp; context_tmp = context_tmp->current)
                     context_tmp->addr_epoch++;
                 
                 if ((lease = lease6_find(state->clid, state->clid_len, state->ia_type == OPTION6_IA_NA ? LEASE_NA : LEASE_TA,
                                          state->iaid, &addr)))
                   lease_prune(lease, now);
                 else
                   {
                     if (!made_ia)
                       {
                         o = new_opt6(state->ia_type);
                         put_opt6_long(state->iaid);
                         if (state->ia_type == OPTION6_IA_NA)
                           {
                             put_opt6_long(0);
                             put_opt6_long(0); 
                           }
                         made_ia = 1;
                       }
                     
                     o1 = new_opt6(OPTION6_IAADDR);
                     put_opt6(&addr, IN6ADDRSZ);
                     put_opt6_long(0);
                     put_opt6_long(0);
                     end_opt6(o1);
                   }
               }
             
             if (made_ia)
               {
                 o1 = new_opt6(OPTION6_STATUS_CODE);
                 put_opt6_short(DHCP6NOBINDING);
                 put_opt6_string(_("no binding found"));
                 end_opt6(o1);
                 
                 end_opt6(o);
               }
             
           }
 
         /* We must answer with 'success' in global section anyway */
         o1 = new_opt6(OPTION6_STATUS_CODE);
         put_opt6_short(DHCP6SUCCESS);
         put_opt6_string(_("success"));
         end_opt6(o1);
         break;
       }
 
     }
   
   log_tags(tagif, state->xid);
   log6_opts(0, state->xid, daemon->outpacket.iov_base + start_opts, daemon->outpacket.iov_base + save_counter(-1));
   
   return 1;
 
 }