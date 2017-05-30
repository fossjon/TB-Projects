/* TB: perform a case-insensitive, size-limited search for a sub-string
       return a pointer to the beg of the substr in the main str
*/
char *substrncase(char *s, char *ss, size_t l) {
    if ((s == NULL) || (ss == NULL)) { return NULL; }
    int f;
    size_t x, y, ll = strlen(ss);
    for (x = 0; x < l; ++x) {
        f = 1;
        for (y = 0; y < ll; ++y) {
            if ((x + y) >= l) { f = 0; break; }
            if (tolower(ss[y]) != tolower(s[x+y])) { f = 0; break; }
        } if (f == 1) { return &(s[x]); }
    }
    return NULL;
}

/* TB: perform a simple charset regex check with inverted matching and error stopping
       return a pointer after the last matched char in the main str
*/
char *searchncase(char *s, size_t l, char *set, int inv, char *end) {
    if ((s == NULL) || (set == NULL) || (end == NULL)) { return NULL; }
    int z, f, i = -1;
    size_t p, x, y, ll = strlen(set), sl = strlen(end);
    for (x = 0; x < l; ++x) {
        f = 0; z = tolower(s[x]);
        for (y = 0; y < sl; ++y) {
            if (z == tolower(end[y])) { return NULL; }
        }
        for (y = 0; y < ll; ++y) {
            if (z == tolower(set[y])) { f = 1; break; }
        }
        if ((inv == 0) && (f == 0)) { break; }
        if ((inv != 0) && (f != 0)) { break; }
        i = 0; p = x;
    }
    if (i < 0) { return NULL; }
    if ((p + 1) < l) { ++p; }
    return &(s[p]);
}

/* TB: provide initial authentication of connecting clients
       return the auth status (0 = fail, 1 = pass & send status back, 2 = pass)
*/
size_t bsub(size_t d, char *a, char *b) {
    if ((a == NULL) || (b == NULL)) { return d; }
    if (a < b) { return d; }
    return (size_t)(a - b);
}
int auth(char *sbuff, size_t *ssize, char *dbuff, size_t *dsize, int *rfd, int *wfd, int *xfd, TB *user) {
    int r, authstat = 0, httpsflag = 0;
    size_t bdiff;
    char port[8], addr[32], host[1024], pipes[2048];
    char *newl = NULL, *pauth = NULL, *ptra, *ptrb;
    char *httpauth = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Access to Tunnel\"\r\n\r\n";
    char *httpgood = "HTTP/1.1 200 OK\r\n\r\n";
    char *httpresp = httpauth;

    if (*ssize < 16) { return authstat; }

    // HTTPS: CONNECT www.google.com:88 HTTP/1.1..Host: www.google.com:88..
    // HTTP: GET http://1.2.3.4:89/example HTTP/1.1..Host: 1.2.3.4:89..
    bzero((char *)port, 8);
    bzero((char *)host, 1024);
    if (memcmp("CONNECT ", sbuff, 8) == 0) {
        strcpy(port, "443");
        httpsflag = 1;
    } else {
        strcpy(port, "80");
        httpsflag = 0;
    }
    // note: remove any HTTP Request-URI absoluteURI prefix (full path references)
    if (httpsflag == 0) {
        char *alpha = "abcdefghijklmnopqrstuvwxyz";
        ptra = searchncase(sbuff, *ssize, alpha, 0, "\r\n"); /* skip the http method */
        while ((bsub(*ssize, ptra, sbuff) < *ssize) && (*ptra == ' ')) { ++ptra; } /* skip spaces */
        if ((ptra != NULL) && (*ptra != '/') && (*ptra != '.')) { /* if this is not a relative path */
            ptrb = searchncase(ptra, (*ssize)-bsub(*ssize, ptra, sbuff), ":", 1, "\r\n"); /* find the proto:// */
            if (((bsub(*ssize, ptrb, sbuff)+3) < *ssize) && (memcmp("://", ptrb, 3) == 0)) {
                ptrb += 3; while ((bsub(*ssize, ptrb, sbuff) < *ssize) && (*ptrb == '/')) { ++ptrb; } /* skip the proto:// */
                ptrb = searchncase(ptrb, (*ssize)-bsub(*ssize, ptrb, sbuff), "/", 1, "\r\n"); /* find the first relative slash */
                if ((ptrb != NULL) && ((bdiff = bsub(*ssize, ptrb, ptra)) < *ssize)) {
                    memmove(ptra, ptrb, (*ssize)-bsub(*ssize, ptrb, sbuff)); /* remove the absolute path */
                    *ssize = ((*ssize) - bdiff);
                }
            }
        }
    }
    // note: parse the HTTP host header value (hostname/address/port)
    ptra = substrncase(sbuff, "Host:", *ssize);
    if (ptra != NULL) {
        ptra += 5; while ((bsub(*ssize, ptra, sbuff) < *ssize) && (*ptra == ' ')) { ++ptra; } /* skip the spaces */
        ptrb = searchncase(ptra, (*ssize)-bsub(*ssize, ptra, sbuff), ":\r\n", 1, ""); /* check for a colon (port) */
        if ((ptrb != NULL) && ((bdiff = bsub(*ssize, ptrb, ptra)) < 1000)) {
            strncpy(host, ptra, bdiff);
            if (*ptrb == ':') {
                ptrb += 1; ptra = searchncase(ptrb, (*ssize)-bsub(*ssize, ptrb, sbuff), "\r\n", 1, ""); /* find end of host header */
                if ((ptra != NULL) && ((bdiff = bsub(*ssize, ptra, ptrb)) < 6)) {
                    strncpy(port, ptrb, bdiff);
                }
            }
        }
    }

    // note: process the proxy authentication HTTP header value
    bzero((char *)addr, 32);
    pauth = substrncase(sbuff, "Proxy-Authorization:", *ssize);
    newl = searchncase(pauth, (*ssize)-bsub(*ssize, pauth, sbuff), "\r\n", 1, "");
    if ((pauth != NULL) && (newl != NULL)) {
        char newt = *newl; *newl = '\0';

        if ((host[0] != '\0') && (port[0] != '\0')) {
            if ((user->sock = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
                unsigned int stat_size = sizeof(user->stat);
                struct timeval time_outs;

                // note: gather & send the needed info to the internal auth service
                time_outs.tv_sec = 3; time_outs.tv_usec = 0;
                setsockopt(user->sock, SOL_SOCKET, SO_RCVTIMEO, &time_outs, sizeof(time_outs));

                bzero((char *)&(user->stat), stat_size);
                user->stat.sin_family = AF_INET;
                user->stat.sin_addr.s_addr = inet_addr("127.0.0.1");
                user->stat.sin_port = htons(3131);

                bzero((char *)pipes, 2048);
                snprintf(pipes, 2000, "auth %s %s %s %s", host, port, user->addr, pauth);
                sendto(user->sock, pipes, strlen(pipes), 0, (struct sockaddr *)&(user->stat), stat_size);

                bzero((char *)pipes, 1024);
                recvfrom(user->sock, pipes, 1000, 0, (struct sockaddr *)&(user->stat), &stat_size);

                // note: process the auth service response: "PASS|FAIL username ipaddress"
                if (memcmp("PASS", pipes, 4) == 0) {
                    ptra = (pipes + 5); ptrb = searchncase(ptra, 900, " ", 1, "");
                    if ((ptrb != NULL) && ((bdiff = bsub(900, ptrb, ptra)) < 900)) {
                        bzero((char *)user->name, 1024);
                        strncpy(user->name, ptra, bdiff); ptrb += 1; bdiff += 5;
                        size_t l = strlen(pipes); if (l > 0) { --l; }
                        while ((l > 0) && ((pipes[l] == '\r') || (pipes[l] == '\n'))) { --l; }
                        if ((l > bdiff) && ((l - bdiff) < 21)) { strncpy(addr, ptrb, l-bdiff); }
                    }
                    printf("AUTH:[%s][%s][%s][%s]\n", user->name, user->addr, addr, port);
                }
            }
        }

        *newl = newt;

        strcpy(pauth, "X-Auth: z"); pauth += 9;
        while (pauth < newl) { *pauth = 'z'; ++pauth; }
    }

    /*printf("TB-DATA:[%zd][", *ssize);
    for (size_t x = 0; x < *ssize; ++x) {
        if (sbuff[x] < 32) { printf("\\%d", sbuff[x]); }
        else { printf("%c", sbuff[x]); }
    } printf("]\n");*/

    // note: if we have authenticated and have a proper HTTP request then connect to a new socket
    if ((user->name[0] != '\0') && (addr[0] != '\0') && (port[0] != '\0')) {
        if ((r = socket(AF_INET, SOCK_STREAM, 0)) >= 0) {
            struct sockaddr_in sockobjc;
            bzero((char *)&sockobjc, sizeof(sockobjc));
            sockobjc.sin_family = AF_INET;
            sockobjc.sin_addr.s_addr = inet_addr(addr);
            sockobjc.sin_port = htons(atoi(port));
            if (connect(r, (struct sockaddr *)&sockobjc, sizeof(sockobjc)) >= 0) {
                if (httpsflag == 0) { httpresp = NULL; authstat = 2; }
                else { httpresp = httpgood; authstat = 1; }
                closesocket(*rfd);
                *rfd = r; *wfd = *rfd; *xfd = *wfd;
            } else {
                closesocket(r);
            }
        }
    }

    if (httpresp != NULL) {
        *dsize = strlen(httpresp);
        bcopy((char *)httpresp, (char *)dbuff, *dsize);
    }

    return authstat;
}

/* TB: send the user data usage stats to our helper service
*/
void data(int sock, struct sockaddr_in stat, char *user, unsigned long long used) {
    char byte_str[2048];
    bzero((char *)byte_str, 2048);
    snprintf(byte_str, 2000, "data %s %llu", user, used);
    sendto(sock, byte_str, strlen(byte_str), 0, (struct sockaddr *)&stat, sizeof(stat));
}
