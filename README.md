## suricata 网卡抓包模式分析

suricata在linux下主要的抓包模式为af-packet，这种抓包模式需要suricata先创建raw socket，然后利用tap网卡将系统流量镜像复制一份到我们的socket上。在这里需要解释一下raw socket与平常我们所说的socket之间的区别。在AF_INET下有三种套接字：流套接字（SOCK_STREAM), 数据包套接字（SOCK_DGRAM）和原始套接字（SOCK_RAW）。通常基于tcp或者udp的应用程序通信用前两种就能满足，但如ICMP等其它类型传输层协议就无法通过这样的socket进行通信。我们的suricata本身就有着与sniffer类似的功能，使用自身设计的协议栈来完成协议解析功能。那么raw socket就为我们的程序提供了网络层以上的所有数据，而不仅仅是tcp，udp数据供我们程序进行解析。

suricata创建socket方式
You can use the [editor on GitHub](https://github.com/scarletttt/scarletttt.github.io/edit/master/README.md) to maintain and preview the content for your website in Markdown files.

Whenever you commit to this repository, GitHub Pages will run [Jekyll](https://jekyllrb.com/) to rebuild the pages in your site, from the content in your Markdown files.

### Markdown

Markdown is a lightweight and easy-to-use syntax for styling your writing. It includes conventions for

```markdown
static int AFPCreateSocket(AFPThreadVars *ptv, char *devname, int verbose)
{
    int r;
    int ret = AFP_FATAL_ERROR;
    struct packet_mreq sock_params;
    struct sockaddr_ll bind_address;
    int if_idx;

    /* open socket */
    ptv->socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (ptv->socket == -1) {
        SCLogError(SC_ERR_AFP_CREATE, "Couldn't create a AF_PACKET socket, error %s", strerror(errno));
        goto error;
    }

    if_idx = AFPGetIfnumByDev(ptv->socket, devname, verbose);

    if (if_idx == -1) {
        goto socket_err;
    }

    /* bind socket */
    memset(&bind_address, 0, sizeof(bind_address));
    bind_address.sll_family = AF_PACKET;
    bind_address.sll_protocol = htons(ETH_P_ALL);
    bind_address.sll_ifindex = if_idx;
    if (bind_address.sll_ifindex == -1) {
        if (verbose)
            SCLogError(SC_ERR_AFP_CREATE, "Couldn't find iface %s", devname);
        ret = AFP_RECOVERABLE_ERROR;
        goto socket_err;
    }

    int if_flags = AFPGetDevFlags(ptv->socket, ptv->iface);
    if (if_flags == -1) {
        if (verbose) {
            SCLogError(SC_ERR_AFP_READ,
                    "Couldn't get flags for interface '%s'",
                    ptv->iface);
        }
        ret = AFP_RECOVERABLE_ERROR;
        goto socket_err;
    } else if ((if_flags & (IFF_UP | IFF_RUNNING)) == 0) {
        if (verbose) {
            SCLogError(SC_ERR_AFP_READ,
                    "Interface '%s' is down",
                    ptv->iface);
        }
        ret = AFP_RECOVERABLE_ERROR;
        goto socket_err;
    }

    if (ptv->promisc != 0) {
        /* Force promiscuous mode */
        memset(&sock_params, 0, sizeof(sock_params));
        sock_params.mr_type = PACKET_MR_PROMISC;
        sock_params.mr_ifindex = bind_address.sll_ifindex;
        r = setsockopt(ptv->socket, SOL_PACKET, PACKET_ADD_MEMBERSHIP,(void *)&sock_params, sizeof(sock_params));
        if (r < 0) {
            SCLogError(SC_ERR_AFP_CREATE,
                    "Couldn't switch iface %s to promiscuous, error %s",
                    devname, strerror(errno));
            goto socket_err;
        }
    }

    if (ptv->checksum_mode == CHECKSUM_VALIDATION_KERNEL) {
        int val = 1;
        if (setsockopt(ptv->socket, SOL_PACKET, PACKET_AUXDATA, &val,
                    sizeof(val)) == -1 && errno != ENOPROTOOPT) {
            SCLogWarning(SC_ERR_NO_AF_PACKET,
                         "'kernel' checksum mode not supported, falling back to full mode.");
            ptv->checksum_mode = CHECKSUM_VALIDATION_ENABLE;
        }
    }

    /* set socket recv buffer size */
    if (ptv->buffer_size != 0) {
        /*
         * Set the socket buffer size to the specified value.
         */
        SCLogPerf("Setting AF_PACKET socket buffer to %d", ptv->buffer_size);
        if (setsockopt(ptv->socket, SOL_SOCKET, SO_RCVBUF,
                       &ptv->buffer_size,
                       sizeof(ptv->buffer_size)) == -1) {
            SCLogError(SC_ERR_AFP_CREATE,
                    "Couldn't set buffer size to %d on iface %s, error %s",
                    ptv->buffer_size, devname, strerror(errno));
            goto socket_err;
        }
    }

    r = bind(ptv->socket, (struct sockaddr *)&bind_address, sizeof(bind_address));
    if (r < 0) {
        if (verbose) {
            if (errno == ENETDOWN) {
                SCLogError(SC_ERR_AFP_CREATE,
                        "Couldn't bind AF_PACKET socket, iface %s is down",
                        devname);
            } else {
                SCLogError(SC_ERR_AFP_CREATE,
                        "Couldn't bind AF_PACKET socket to iface %s, error %s",
                        devname, strerror(errno));
            }
        }
        ret = AFP_RECOVERABLE_ERROR;
        goto socket_err;
    }


#ifdef HAVE_PACKET_FANOUT
    /* add binded socket to fanout group */
    if (ptv->threads > 1) {
        uint16_t mode = ptv->cluster_type;
        uint16_t id = ptv->cluster_id;
        uint32_t option = (mode << 16) | (id & 0xffff);
        r = setsockopt(ptv->socket, SOL_PACKET, PACKET_FANOUT,(void *)&option, sizeof(option));
        if (r < 0) {
            SCLogError(SC_ERR_AFP_CREATE,
                       "Couldn't set fanout mode, error %s",
                       strerror(errno));
            goto socket_err;
        }
    }
#endif

#ifdef HAVE_PACKET_EBPF
    if (ptv->cluster_type == PACKET_FANOUT_EBPF) {
        r = SockFanoutSeteBPF(ptv);
        if (r < 0) {
            SCLogError(SC_ERR_AFP_CREATE,
                       "Coudn't set EBPF, error %s",
                       strerror(errno));
            goto socket_err;
        }
    }
#endif

    if (ptv->flags & AFP_RING_MODE) {
        ret = AFPSetupRing(ptv, devname);
        if (ret != 0)
            goto socket_err;
    }

    SCLogDebug("Using interface '%s' via socket %d", (char *)devname, ptv->socket);

    ptv->datalink = AFPGetDevLinktype(ptv->socket, ptv->iface);
    switch (ptv->datalink) {
        case ARPHRD_PPP:
        case ARPHRD_ATM:
            ptv->cooked = 1;
            break;
    }

    TmEcode rc = AFPSetBPFFilter(ptv);
    if (rc == TM_ECODE_FAILED) {
        ret = AFP_FATAL_ERROR;
        goto socket_err;
    }

    /* Init is ok */
    AFPSwitchState(ptv, AFP_STATE_UP);
    return 0;

socket_err:
    close(ptv->socket);
    ptv->socket = -1;
    if (ptv->flags & AFP_TPACKET_V3) {
        if (ptv->ring.v3) {
            SCFree(ptv->ring.v3);
            ptv->ring.v3 = NULL;
        }
    } else {
        if (ptv->ring.v2) {
            SCFree(ptv->ring.v2);
            ptv->ring.v2 = NULL;
        }
    }

error:
    return -ret;
}

```

For more details see [GitHub Flavored Markdown](https://guides.github.com/features/mastering-markdown/).

### Jekyll Themes

Your Pages site will use the layout and styles from the Jekyll theme you have selected in your [repository settings](https://github.com/scarletttt/scarletttt.github.io/settings). The name of this theme is saved in the Jekyll `_config.yml` configuration file.

### Support or Contact

Having trouble with Pages? Check out our [documentation](https://help.github.com/categories/github-pages-basics/) or [contact support](https://github.com/contact) and we’ll help you sort it out.
