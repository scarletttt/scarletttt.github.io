## suricata 网卡抓包模式分析

suricata在linux下主要的抓包模式为af-packet，这种抓包模式需要suricata先创建raw socket，然后利用tap网卡将系统流量镜像复制一份到我们的socket上。在这里需要解释一下raw socket与平常我们所说的socket之间的区别。在AF_INET下有三种套接字：流套接字（SOCK_STREAM), 数据包套接字（SOCK_DGRAM）和原始套接字（SOCK_RAW）。通常基于tcp或者udp的应用程序通信用前两种就能满足，但如ICMP等其它类型传输层协议就无法通过这样的socket进行通信。我们的suricata本身就有着与sniffer类似的功能，使用自身设计的协议栈来完成协议解析功能。那么raw socket就为我们的程序提供了网络层以上的所有数据，而不仅仅是tcp，udp数据供我们程序进行解析。

You can use the [editor on GitHub](https://github.com/scarletttt/scarletttt.github.io/edit/master/README.md) to maintain and preview the content for your website in Markdown files.

Whenever you commit to this repository, GitHub Pages will run [Jekyll](https://jekyllrb.com/) to rebuild the pages in your site, from the content in your Markdown files.

### Markdown

Markdown is a lightweight and easy-to-use syntax for styling your writing. It includes conventions for

```markdown
Syntax highlighted code block

# Header 1
## Header 2
### Header 3

- Bulleted
- List

1. Numbered
2. List

**Bold** and _Italic_ and `Code` text

[Link](url) and ![Image](src)
```

For more details see [GitHub Flavored Markdown](https://guides.github.com/features/mastering-markdown/).

### Jekyll Themes

Your Pages site will use the layout and styles from the Jekyll theme you have selected in your [repository settings](https://github.com/scarletttt/scarletttt.github.io/settings). The name of this theme is saved in the Jekyll `_config.yml` configuration file.

### Support or Contact

Having trouble with Pages? Check out our [documentation](https://help.github.com/categories/github-pages-basics/) or [contact support](https://github.com/contact) and we’ll help you sort it out.
