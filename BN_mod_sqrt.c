static CURLcode ssh_check_fingerprint(struct Curl_easy *data)
{
  struct connectdata *conn = data->conn;
  struct ssh_conn *sshc = &conn->proto.sshc;
  const char *pubkey_md5 = data->set.str[STRING_SSH_HOST_PUBLIC_KEY_MD5];
  const char *pubkey_sha256 = data->set.str[STRING_SSH_HOST_PUBLIC_KEY_SHA256];
  infof(data, "SSH MD5 public key: %s",
    pubkey_md5 != NULL ? pubkey_md5 : "NULL");
  infof(data, "SSH SHA256 public key: %s",
      pubkey_sha256 != NULL ? pubkey_sha256 : "NULL");
  if(pubkey_sha256) {
    const char *fingerprint = NULL;
    char *fingerprint_b64 = NULL;
    size_t fingerprint_b64_len;
    size_t pub_pos = 0;
    size_t b64_pos = 0;
#ifdef LIBSSH2_HOSTKEY_HASH_SHA256
    /* The fingerprint points to static storage (!), don't free() it. */
    fingerprint = libssh2_hostkey_hash(sshc->ssh_session,
        LIBSSH2_HOSTKEY_HASH_SHA256);
#else
    const char *hostkey;
    size_t len = 0;
    unsigned char hash[32];
    hostkey = libssh2_session_hostkey(sshc->ssh_session, &len, NULL);
    if(hostkey) {
      Curl_sha256it(hash, (const unsigned char *) hostkey, len);
      fingerprint = (char *) hash;
    }
#endif
    if(!fingerprint) {
      failf(data,
          "Denied establishing ssh session: sha256 fingerprint "
          "not available");
      state(data, SSH_SESSION_FREE);
      sshc->actualcode = CURLE_PEER_FAILED_VERIFICATION;
      return sshc->actualcode;
    }
    /* The length of fingerprint is 32 bytes for SHA256.
     * See libssh2_hostkey_hash documentation. */
    if(Curl_base64_encode (data, fingerprint, 32, &fingerprint_b64,
        &fingerprint_b64_len) != CURLE_OK) {
      state(data, SSH_SESSION_FREE);
      sshc->actualcode = CURLE_PEER_FAILED_VERIFICATION;
      return sshc->actualcode;
    }
    if(!fingerprint_b64) {
      failf(data,
          "sha256 fingerprint could not be encoded");
      state(data, SSH_SESSION_FREE);
      sshc->actualcode = CURLE_PEER_FAILED_VERIFICATION;
      return sshc->actualcode;
    }
    infof(data, "SSH SHA256 fingerprint: %s", fingerprint_b64);
    /* Find the position of any = padding characters in the public key */
    while((pubkey_sha256[pub_pos] != '=') && pubkey_sha256[pub_pos]) {
      pub_pos++;
    }
    /* Find the position of any = padding characters in the base64 coded
     * hostkey fingerprint */
    while((fingerprint_b64[b64_pos] != '=') && fingerprint_b64[b64_pos]) {
      b64_pos++;
    }
    /* Before we authenticate we check the hostkey's sha256 fingerprint
     * against a known fingerprint, if available.
     */
    if((pub_pos != b64_pos) ||
        Curl_strncasecompare(fingerprint_b64, pubkey_sha256, pub_pos) != 1) {
      free(fingerprint_b64);

      failf(data,
          "Denied establishing ssh session: mismatch sha256 fingerprint. "
          "Remote %s is not equal to %s", fingerprint, pubkey_sha256);
      state(data, SSH_SESSION_FREE);
      sshc->actualcode = CURLE_PEER_FAILED_VERIFICATION;
      return sshc->actualcode;
    }
    free(fingerprint_b64);
    infof(data, "SHA256 checksum match!");
  }
  if(pubkey_md5) {
    char md5buffer[33];
    const char *fingerprint = NULL;
    fingerprint = libssh2_hostkey_hash(sshc->ssh_session,
        LIBSSH2_HOSTKEY_HASH_MD5);
    if(fingerprint) {
      /* The fingerprint points to static storage (!), don't free() it. */
      int i;
      for(i = 0; i < 16; i++) {
        msnprintf(&md5buffer[i*2], 3, "%02x", (unsigned char) fingerprint[i]);
      }
      infof(data, "SSH MD5 fingerprint: %s", md5buffer);
    }
    /* Before we authenticate we check the hostkey's MD5 fingerprint
     * against a known fingerprint, if available.
     */
    if(pubkey_md5 && strlen(pubkey_md5) == 32) {
      if(!fingerprint || !strcasecompare(md5buffer, pubkey_md5)) {
        if(fingerprint) {
          failf(data,
              "Denied establishing ssh session: mismatch md5 fingerprint. "
              "Remote %s is not equal to %s", md5buffer, pubkey_md5);
        }
        else {
          failf(data,
              "Denied establishing ssh session: md5 fingerprint "
              "not available");
        }
        state(data, SSH_SESSION_FREE);
        sshc->actualcode = CURLE_PEER_FAILED_VERIFICATION;
        return sshc->actualcode;
      }
      infof(data, "MD5 checksum match!");
    }
  }
  if(!pubkey_md5 && !pubkey_sha256) {
    return ssh_knownhost(data);
  }
  else {
    /* as we already matched, we skip the check for known hosts */
    return CURLE_OK;
  }
}