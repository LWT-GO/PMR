# PMR: Fast Application Response via Parallel Memory Reclaim on Mobile Devices
This repo contains the code written for PMR: Fast Application Response via Parallel Memory Reclaim on Mobile Devices (published in USENIX ATC'25). For more detail about the project, please refer to our [paper](https://www.usenix.org/conference/atc25/presentation/li-wentong).


# What is PMR? 

The basic idea is of PMR to parallelize key steps of memory reclaim to fulfill application memory demand and thus improve application response. Intuitively, there are two typical
ways to perform parallel memory reclaim. First, the kernel can create multiple memory reclaim threads, e.g., [Mutiple kswapd](https://lkml.org/lkml/2018/4/2/107) wakes up multiple kswapd threads to perform memory swapping to relieve memory pressure. Second, it is possible to exploit the performance advantage of flash storage through bulk I/Os. For example, [SEAL](https://ieeexplore.ieee.org/document/9211475) performs
memory swapping in units of applications, rather than page by page. However, for the former, multi-threaded memory reclaim is prone to conflict with each other and burden the CPU because they occur simultaneously. For the latter, simply increasing the I/O size still does not resolve the suboptimal execution flow of memory reclaim. Unlike previous work, PMR parallelizes key steps in the memory reclaim path based on the below observations:

- page writeback waits on the results of page shrinking, introducing unnecessary delays;
- page shrinking suffers from inefficient reclaim and repeated invocation
- page unmap latency is highly unstable and produces small writes that cannot unleash the potential of flash storage.

The overview of PMR is shown in the picture.

<img width="488" height="281" alt="image" src="https://github.com/user-attachments/assets/6533a64f-4b2a-4c6b-b2d1-979dac670b39" />

# Maintainer
Wentong Li [email](liwentongemail@gmail.com)

Tips: This repository code will be continuously updated once the code has passed necessary checks.
