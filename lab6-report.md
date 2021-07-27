# lab6 Firewall Exploration Lab

#### 51778204 陈盈

## Environment Setup Using Containers

![image-20210726152746769](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726152746769.png)

查看各主机的哈希值。



## ![image-20210726183115808](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726183115808.png)

##  Task 1: Implementing a Simple Firewall

###  Task 1.A: Implement a Simple Kernel Module

对kernel_modules进行编译。

![image-20210726154156263](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726154156263.png)

测试以下命令。

![image-20210726154418722](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726154418722.png)

![image-20210726154517418](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726154517418.png)

### Task 1.B: Implement a Simple Firewall Using Netfilter

#### 1

和task1.A一样，对文件进行编译。

![image-20210726154644489](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726154644489.png)

加载内核前，可以看到 dig @8.8.8.8 www.example 命令可以得到响应。

![image-20210726155042799](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726155042799.png)

加载内核后，防火墙生效， dig @8.8.8.8 www.example 命令得不到响应。

![image-20210726155253270](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726155253270.png)

完成任务后移除内核。

![image-20210726155340399](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726155340399.png)

#### 2

进行 dig @8.8.8.8 www.example.com 操作后，可使用 sudo dmesg -c 查看信息，每次测试后，需要运行 sudo rmmod seedFilter 从内核中移除模块。

未加载内核时dig @8.8.8.8 www.example.com。

![image-20210726155928053](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726155928053.png)

修改seedFilter.c文件，代码如下。

```c
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/inet.h>


static struct nf_hook_ops hook1, hook2,hook3, hook4, hook5; 


unsigned int blockUDP(void *priv, struct sk_buff *skb,
                       const struct nf_hook_state *state)
{
   struct iphdr *iph;
   struct udphdr *udph;

   u16  port   = 53;
   char ip[16] = "8.8.8.8";
   u32  ip_addr;

   if (!skb) return NF_ACCEPT;

   iph = ip_hdr(skb);
   // Convert the IPv4 address from dotted decimal to 32-bit binary
   in4_pton(ip, -1, (u8 *)&ip_addr, '\0', NULL);

   if (iph->protocol == IPPROTO_UDP) {
       udph = udp_hdr(skb);
       if (iph->daddr == ip_addr && ntohs(udph->dest) == port){
            printk(KERN_WARNING "*** Dropping %pI4 (UDP), port %d\n", &(iph->daddr), port);
            return NF_DROP;
        }
   }
   return NF_ACCEPT;
}

unsigned int printInfo(void *priv, struct sk_buff *skb,
                 const struct nf_hook_state *state)
{
   struct iphdr *iph;
   char *hook;
   char *protocol;

   switch (state->hook){
     case NF_INET_LOCAL_IN:     hook = "LOCAL_IN";     break; 
     case NF_INET_LOCAL_OUT:    hook = "LOCAL_OUT";    break; 
     case NF_INET_PRE_ROUTING:  hook = "PRE_ROUTING";  break; 
     case NF_INET_POST_ROUTING: hook = "POST_ROUTING"; break; 
     case NF_INET_FORWARD:      hook = "FORWARD";      break; 
     default:                   hook = "IMPOSSIBLE";   break;
   }
   printk(KERN_INFO "*** %s\n", hook); // Print out the hook info

   iph = ip_hdr(skb);
   switch (iph->protocol){
     case IPPROTO_UDP:  protocol = "UDP";   break;
     case IPPROTO_TCP:  protocol = "TCP";   break;
     case IPPROTO_ICMP: protocol = "ICMP";  break;
     default:           protocol = "OTHER"; break;

   }
   // Print out the IP addresses and protocol
   printk(KERN_INFO "    %pI4  --> %pI4 (%s)\n", 
                    &(iph->saddr), &(iph->daddr), protocol);

   return NF_ACCEPT;
}



int registerFilter(void) {
printk(KERN_INFO "Registering filters.\n");
// Hook 1
hook1.hook = printInfo; 
hook1.hooknum = NF_INET_LOCAL_IN; 
hook1.pf = PF_INET;
hook1.priority = NF_IP_PRI_FIRST;
nf_register_net_hook(&init_net, &hook1); 
// Hook 2
hook2.hook = printInfo; 
hook2.hooknum = NF_INET_PRE_ROUTING; 
hook2.pf = PF_INET;
hook2.priority = NF_IP_PRI_FIRST;
nf_register_net_hook(&init_net, &hook2); 
// Hook 3
hook3.hook = printInfo; 
hook3.hooknum = NF_INET_FORWARD; 
hook3.pf = PF_INET;
hook3.priority = NF_IP_PRI_FIRST;
nf_register_net_hook(&init_net, &hook3); 
// Hook 4
hook4.hook = printInfo; 
hook4.hooknum = NF_INET_LOCAL_OUT; 
hook4.pf = PF_INET;
hook4.priority = NF_IP_PRI_FIRST;
nf_register_net_hook(&init_net, &hook4); 
// Hook 5
hook5.hook = printInfo; 
hook5.hooknum = NF_INET_POST_ROUTING; 
hook5.pf = PF_INET;
hook5.priority = NF_IP_PRI_FIRST;
nf_register_net_hook(&init_net, &hook5); 
return 0;
}
void removeFilter(void) {
printk(KERN_INFO "The filters are being removed.\n");
nf_unregister_net_hook(&init_net, &hook1);
nf_unregister_net_hook(&init_net, &hook2);
nf_unregister_net_hook(&init_net, &hook3);
nf_unregister_net_hook(&init_net, &hook4);
nf_unregister_net_hook(&init_net, &hook5);
}
module_init(registerFilter);
module_exit(removeFilter);
MODULE_LICENSE("GPL");
```

编译文件并装载内核。

![image-20210726182842722](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726182842722.png)

在用户主机上ping攻击者主机，得到结果如下，可知能够连接。

![image-20210726183418936](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726183418936.png)



![image-20210726183641907](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726183641907.png)

![image-20210726183343940](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726183343940.png)

![image-20210726183849330](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726183849330.png)

ping外部主机

![image-20210726183822530](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726183822530.png)

![image-20210726184033775](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726184033775.png)

数据报从进入系统，进行 IP 校验以后，首先经过第一个 HOOK 函数 NF_INET_PRE_ROUTING 进行处理， 然后就进入路由代码，其决定该数据报是需要转发还是发给本机的。若该数据报应该被转发则它被 NF_INET_FORWARD 处理。

挂载 NF_INET_LOCAL_OUT 时，本机产生的数据包将会第一个到达此 HOOK ，数据经过 HOOK 函数 NF_INET_LOCAL_OUT 处理后，进行路由选择处理，然后经过NF_INET_POST_ROUTING 处理后发送出去。

经过转发的数据报经过最后一个 HOOK 函数 NF_INET_POST_ROUTING 处理以后，再传输到网络上。

#### 3

修改seedFilter.c文件，代码如下：

```c
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static struct nf_hook_ops telnetFilterHook;

unsigned int telnetFilter(void *priv, struct sk_buff * skb, const struct nf_hook_state *state){

            struct iphdr *iph;
            struct tcphdr *tcph;
            iph = ip_hdr(skb);
            tcph = (void *)iph+iph->ihl*4;

            if((iph->protocol == IPPROTO_TCP && (tcph->dest == htons(23) 
              || tcph->dest== htons(22) 
              || tcph->dest== htons(21)))  
              || (iph->protocol == IPPROTO_ICMP &&((((unsigned char *)&iph->daddr)[0]==10 &&  
                 ((unsigned char *)&iph->daddr)[1]==9 
                 && ((unsigned char *)&iph->daddr)[2]==0 && ((unsigned char *)&iph->daddr)[3]==1)
              || (((unsigned char *)&iph->daddr)[0]==10 &&  ((unsigned char *)&iph->daddr)[1]==9 
                 && ((unsigned char *)&iph->daddr)[2]==0 && ((unsigned char *)&iph->daddr)[3]==1)))){
                printk(KERN_INFO "Dropping telent packdt to %d.%d.%d.%d\n",
                ((unsigned char *)&iph->daddr)[0],
                ((unsigned char *)&iph->daddr)[1],
                ((unsigned char *)&iph->daddr)[2],
                ((unsigned char *)&iph->daddr)[3]);
                return NF_DROP;
            }else{
                return NF_ACCEPT;
            }        
        }
void removeFilter(void){
    printk(KERN_INFO "Telnet filter has been removed.\n");
    nf_unregister_net_hook(&init_net,&telnetFilterHook);
}

int setUpFilter(void){
    
    telnetFilterHook.hook = telnetFilter;
    telnetFilterHook.hooknum = NF_INET_PRE_ROUTING;
    telnetFilterHook.pf = PF_INET;
    telnetFilterHook.priority = NF_IP_PRI_FILTER;

    if(nf_register_net_hook(&init_net,&telnetFilterHook)!=0){
        printk(KERN_WARNING "register Telnet filter hook error!\n");
        goto err;
    }
    printk(KERN_INFO "Registering a Telnet filter");
    return 0;

err:
    removeFilter();
    return -1;
}

module_init(setUpFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");
```

编译文件并加载内核。

![image-20210726184359699](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726184359699.png)

在主机A(10.9.0.5)分别进行 ping 10.9.0.1 和 telnet 10.9.0.1 。

![image-20210726184430458](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726184430458.png)

![image-20210726184515475](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726184515475.png)

在本机上查看内核缓存。

![image-20210726184545134](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726184545134.png)

## Task 2: Experimenting with Stateless Firewall Rules

每个任务前都要清理 table。

###  Task 2.A: Protecting the Router

按要求在router上输入以下命令。

![image-20210726190034162](D:\markdown\Typora\image-20210726190034162.png)

在主机A（10.9.0.5）上， ping 10.9.0.11 和 telnet 10.9.0.11 都不通。

![image-20210726190244063](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726190244063.png)

将命令换成如下顺序。

![image-20210727215502624](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210727215502624.png)

在主机A（10.9.0.5）上， ping 10.9.0.11通，但 telnet 10.9.0.11 不通。

![image-20210726190435740](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726190435740.png)

![image-20210726190509378](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726190509378.png)

可知该现象的原因是路由器的过滤规则只允许icmp请求报文输入和icmp响应报文输入，ping的报文可以进行传输，儿telent的报文无法进行传输。

### Task 2.B: Protecting the Internal Network

清除table。

![](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726191031115.png)

在router中输入以下命令。

![image-20210726225851508](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726225851508.png)

设置如下：

![image-20210726225802177](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726225802177.png)

从外部主机 ping 路由器，可以 ping 通； ping 内部主机，不通。

![image-20210726231918552](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726231918552.png)

内部主机 ping 外部主机，可以 ping 通； telnet 外部主机，不通。

![image-20210726230328966](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726230328966.png)

###  Task 2.C: Protecting Internal Servers

router中输入以下命令。

![image-20210726232342805](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726232342805.png)

查看设置。

![](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726232649829.png)

从外部主机 (10.9.0.5)telnet 192.168.60.5 ，可以连接成功。

![image-20210726232753124](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726232753124.png)

从外部主机 (10.9.0.5)telnet 192.168.60.6 ，无法连接。

![image-20210726233003005](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726233003005.png)

从内部主机 (192.168.60.5)telnet 10.9.0.5 ，无法连接，内部主机 (192.168.60.5)telnet 192.168.60.6 ，连接成功。

![image-20210726233213417](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726233213417.png)

##  Task 3: Connection Tracking and Stateful Firewall

###  Task 3.A: Experiment with the Connection Tracking

docker重启，哈希值发生变化。

![image-20210726234138392](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726234138392.png)

#### ICMP experiment

在主机A（10.9.0.5）上ping 192.168.60.5

![image-20210726234423531](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726234423531.png)

查看连接状态，ICMP 的连接状态保持时间只有 30 秒左右。

![image-20210726234445399](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726234445399.png)

#### UDP experiment

在主机（ 192.168.60.5）和主机A（10.9.0.5）上建立UDP连接。

![image-20210726234956593](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726234956593.png)

![image-20210726235012128](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726235012128.png)

查看连接状态，UDP 的连接状态保持时间和也只有 20~30 秒之间。

![image-20210726234932258](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726234932258.png)

#### TCP experiment

同上，建立TCP连接。

![image-20210726235500875](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726235500875.png)

![image-20210726235507142](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726235507142.png)

TCP 的连接状态保持时间非常长。

![image-20210726235419734](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726235419734.png)

### Task 3.B: Setting Up a Stateful Firewall

清理table，并输入如下命令。

![image-20210726235824039](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210726235824039.png)

从外部主机 (10.9.0.5)telnet 192.168.60.5。，连接成功 。

![image-20210727000106477](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210727000106477.png)

telnet 192.168.60.6。，连接失败。

![image-20210727000116267](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210727000116267.png)

从内部主机 (192.168.60.5)telnet 10.9.0.5 和 192.168.60.6 ，连接成功。

![image-20210727000436769](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210727000436769.png)

不利用连接跟踪机制的过滤规则仅对数据包的首部进行检查，其优点是处理速度快，缺点是无法定义精细的规则、不适合复杂的访问机制；而利用连接跟踪机制的过滤规则对数据包的状态也进行检查，其优点是能够定义更加严格的规则、应用范围更广、安全性更高，缺点是无法对数据包的内容进行识别。

##  Task 4: Limiting Network Traffic

在router上利用iptables命令，创建流量限制规则如下。

![image-20210727101851939](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210727101851939.png)

从外部 (10.9.0.5)ping 192.168.60.5 ，得到结果如下，可知能够连接，可以观察到前六个包的速度很快，后面发包速度变慢。

![image-20210727101917375](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210727101917375.png)

如果只执行第一条命令，从外部 (10.9.0.5)ping 192.168.60.5 ，可以观察到和平时的发包速度一 样，因为 iptables 默认的 FORWARD 表是接受所有包，所以如果不写第二条命令，发包会正常进行。

![image-20210727102717499](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210727102717499.png)

![image-20210727102806131](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210727102806131.png)

## Task 5: Load Balancing

#### 使用nth mode

在router上利用iptables命令，采用nth模式创建负载均衡规则如下:

![image-20210727103838628](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210727103838628.png)

发包情况如下，按顺序 hello_1 被发送到 192.168.60.5 8080 ， hello_2 被发送到 192.168.60.6 8080 ， hello_3 被发送到 192.168.60.7 8080。

![image-20210727104135909](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210727104135909.png)

![image-20210727104433391](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210727104433391.png)

![image-20210727104424339](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210727104424339.png)

![image-20210727104459511](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210727104459511.png)

#### random mode

清除之前的iptables规则，router中输入以下规则，等概率发送数据。

![image-20210727104721714](D:\网安课程设计\报告\image-20210727104721714.png)

虽然是等概率发送数据，但每个主机收到的数量各不相同，甚至有的差异较大，当样本数量足够多时， 应该是趋于平均的。

![image-20210727104949792](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210727104949792.png)

![image-20210727105013698](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210727105013698.png)

![image-20210727105042476](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210727105042476.png)

