/*
  Copyright (C) 2008 Tomash Brechko.  All rights reserved.

  When used to build Perl module:

  This library is free software; you can redistribute it and/or modify
  it under the same terms as Perl itself, either Perl version 5.8.8
  or, at your option, any later version of Perl 5 you may have
  available.

  When used as a standalone library:

  This library is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of the
  License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.
*/

#include <ws2tcpip.h>
#include "poll.h"

int
poll(struct pollfd *fds, int nfds, int timeout)
{
  fd_set read_set, write_set, exception_set;
  struct timeval to, *pto;
  int max_fd = -1;
  int select_res, poll_res;
  int i;

  if (timeout >= 0)
    {
      pto = &to;
      pto->tv_sec = timeout / 1000;
      pto->tv_usec = (timeout % 1000) * 1000;
    }
  else
    {
      pto = NULL;
    }

  FD_ZERO(&read_set);
  FD_ZERO(&write_set);
  FD_ZERO(&exception_set);

  for (i = 0; i < nfds; ++i)
    {
      fds[i].revents = 0;

      /* POSIX requires skipping fd less than zero.  */
      if (fds[i].fd < 0)
        continue;

      if (max_fd < fds[i].fd)
        max_fd = fds[i].fd;

      if (fds[i].events & POLLIN)
        FD_SET(fds[i].fd, &read_set);
      if (fds[i].events & POLLOUT)
        FD_SET(fds[i].fd, &write_set);
      /*
        poll() waits for error condition even when no other event is
        requested (events == 0).  POSIX says that pending socket error
        should be an exceptional condition.  However other exceptional
        conditions are protocol-specific.  For instance for TCP
        out-of-band data is often also exceptional.  So we enable
        exceptions unconditionally, and callers should treat returned
        POLLERR as "may read/write".
      */
      FD_SET(fds[i].fd, &exception_set);
    }

  select_res = select(max_fd + 1, &read_set, &write_set, &exception_set, pto);

  if (select_res > 0)
    {
      /*
        select() returns number of bits set, but poll() returns number
        of flagged structures.
      */
      poll_res = 0;
      for (i = 0; i < nfds; ++i)
        {
          if (FD_ISSET(fds[i].fd, &read_set))
            {
              fds[i].revents |= POLLIN;
              --select_res;
            }
          if (FD_ISSET(fds[i].fd, &write_set))
            {
              fds[i].revents |= POLLOUT;
              --select_res;
            }
          if (FD_ISSET(fds[i].fd, &exception_set))
            {
              fds[i].revents |= POLLERR;
              --select_res;
            }

          if (fds[i].revents != 0)
            {
              ++poll_res;

              if (select_res == 0)
                break;
            }
        }
    }
  else
    {
      poll_res = select_res;
    }

  errno = WSAGetLastError();
  return poll_res;
}

#ifdef h_addr
#define ADDR(host, i)  host->h_addr_list[i]
#else  /* ! h_addr */
#define ADDR(host, i)  host->h_addr
#endif /* ! h_addr */

#define FILL_SOCKADDR(AF_INET, sockaddr_in, sin, s,             \
                      host, port, count, addrlen, addrs)        \
  do                                                            \
    {                                                           \
      struct sockaddr_in *addr;                                 \
      int i;                                                    \
                                                                \
      addrlen = sizeof(struct sockaddr_in);                     \
                                                                \
      addr = (struct sockaddr_in *) calloc(count, addrlen);     \
      for (i = 0; i < count; ++i)                               \
        {                                                       \
          addr[i].sin##_family = AF_INET;                       \
          addr[i].sin##_port = port;                            \
          memcpy(&addr[i].sin##_addr.s##_addr,                  \
                 ADDR(host, i), host->h_length);                \
        }                                                       \
                                                                \
      addrs = (char *) addr;                                    \
    }                                                           \
  while (0)

#define fill_sockaddr(host, port, count, addrlen, addrs)        \
  FILL_SOCKADDR(AF_INET, sockaddr_in, sin, s,                   \
                host, port, count, addrlen, addrs)

#ifdef AF_INET6
#define fill_sockaddr6(host, port, count, addrlen, addrs)       \
  FILL_SOCKADDR(AF_INET6, sockaddr_in6, sin6, s6,               \
                host, port, count, addrlen, addrs)
#endif  /* AF_INET6 */

#ifndef getaddrinfo

int
getaddrinfo(const char *node, const char *service,
                    const struct addrinfo *hints,
                    struct addrinfo **res)
{
  struct hostent *host;
  struct servent *serv;
  int count, i;
  int port;
  char *name;
  size_t addrlen;
  char *addrs;
  struct addrinfo *addrinfos;

  host = gethostbyname(node);
  if (! host
      || (hints->ai_family != AF_UNSPEC
          && host->h_addrtype != hints->ai_family))
    return -1;

  count = 1;
#ifdef h_addr
  while (host->h_addr_list[count])
    ++count;
#endif  /* h_addr */

  serv = getservbyname(service, (hints->ai_socktype == SOCK_STREAM
                                 ? "tcp" : "udp"));
  port = serv ? serv->s_port : htons(atoi(service));

  if (host->h_name)
    {
      size_t name_len = strlen(host->h_name);
      name = (char *) malloc(name_len + 1);
      memcpy(name, host->h_name, name_len + 1);
    }
  else
    {
      name = NULL;
    }

#ifdef AF_INET6
  if (host->h_addrtype == AF_INET6)
    fill_sockaddr6(host, port, count, addrlen, addrs);
  else
#endif  /* AF_INET6 */
    fill_sockaddr(host, port, count, addrlen, addrs);


  addrinfos = (struct addrinfo *) malloc(sizeof(*addrinfos) * count);
  addrinfos[0].ai_flags = hints->ai_flags;
  addrinfos[0].ai_family = host->h_addrtype;
  addrinfos[0].ai_socktype = hints->ai_socktype;
  addrinfos[0].ai_protocol = hints->ai_protocol;
  addrinfos[0].ai_addrlen = addrlen;
  addrinfos[0].ai_addr = (struct sockaddr *) addrs;
  addrinfos[0].ai_canonname = name;
  for (i = 1; i < count; ++i)
    {
      addrinfos[i] = addrinfos[0];

      addrinfos[i].ai_addr = (struct sockaddr *) (addrs + addrlen * i);
      addrinfos[i - 1].ai_next = &addrinfos[i];
    }
  addrinfos[i - 1].ai_next = NULL;

  *res = addrinfos;

  return 0;
}

#endif

#ifndef freeaddrinfo

void
freeaddrinfo(struct addrinfo *res)
{
  free(res->ai_addr);
  free(res->ai_canonname);
  free(res);
}

#endif