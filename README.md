# Hopping

The "hopping" program is an efficient way to determine how many hops there are to a given destination. It is more efficient and convenient to use than traceroute.

The software is under development, and subject to research on best algorithms for determining the number of hops, but the basic idea is that if you need to determine the number of hops, sequential processes such as those in traceroute may not be optimal. For instance, to find out how far facebook.com is from a current network, we can use hopping in different modes to compare their performance:

    # ./hopping -quiet -statistics -algorithm binarysearch facebook.com
    facebook.com (157.240.20.35) is 12 hops away and reachable
    8 probes sent

So, 8 probes were needed to determine that facebook.com is 12 hops away. This number could be still improved with the implementation of various heuristics, but that is ongoing work. However, even now, if you compare to a sequential search, you get 13 probes needed for that:

    # ./hopping -quiet -statistics -algorithm sequential facebook.com
    facebook.com (185.60.216.35) is 12 hops away and reachable
    13 probes sent

Interestingly, even a completely *random* process will improve the performance of the sequential search:

    # ./hopping -quiet -statistics -algorithm random facebook.com
    facebook.com (157.240.20.35) is 12 hops away and reachable
    10 probes sent

# Usage

# Installation

The easiest installation method is to retrieve the software from GitHub:

    git clone https://github.com/jariarkko/hopping.git
    sudo make all install
