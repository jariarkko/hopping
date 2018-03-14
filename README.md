# Hopping

## An Efficient Hop Counter

The "hopping" program is an efficient way to determine how many hops there are to a given destination. It is more efficient and convenient to use than traceroute.

This program is a part of the Architecture Tester (archtester) collection of tools. See https://github.com/jariarkko/archtester. The tool has been written by Jari Arkko as a private project.

The hopping software is under development, and subject to research on best algorithms for determining the number of hops, but the basic idea is that if you need to determine the number of hops, sequential processes such as those in traceroute may not be optimal. For instance, to find out how far facebook.com is from a current network, we can use hopping in different modes to compare their performance:

    # hopping -quiet -statistics -algorithm binarysearch facebook.com
    facebook.com (157.240.20.35) is 12 hops away and reachable
    8 probes sent

So, 8 probes were needed to determine that facebook.com is 12 hops away using a binary search process. This number could be still improved with the implementation of various heuristics, as the current software starts testing at TTLs 127 and 63 initially, far above what is a likely value in any practical Internet setting.

Nevertheless, even the 8 probes is an improvement over the 13 probes needed for the sequential search:

    # hopping -quiet -statistics -algorithm sequential facebook.com
    facebook.com (185.60.216.35) is 12 hops away and reachable
    13 probes sent

Interestingly, even a completely *random* process will improve the performance of the sequential search:

    # hopping -quiet -statistics -algorithm random facebook.com
    facebook.com (157.240.20.35) is 12 hops away and reachable
    10 probes sent

# Usage

The software is packaged as the "hopping" utility, and typing

    # hopping example.com

for some destination will usually work fine. However, for fine-tuning there are a number of different options. The full syntax is

    hopping [options] destination

where the options are as follows:

    -version

Outputs the version number

    -debug
    -no-debug

Sets the debugging output on/off.

    -quiet
    -no-progress
    -progress
    -detailed-progress
    -detailed-progress-and-probe-status

Forces hopping to report various amounts of information about the status of the search as it works. The option -quiet is a synonym for -no-progress. The default is -progress.

    -no-statistics
    -statistics
    -full-statistics

Makes hopping provide various levels of final statistics report of what probes were sent and responses received.

    -machine-readable
    -human-readable

These controls affect the output of summary and statistics information, whether it is expected to be human or machine readable. The default is human readable.

    -size n

Makes the ICMP messages used in the process carry n bytes of data. The default is zero, so (for IPv4) the probe packet size will be 28 bytes.

    -maxttl n

Sets the software to avoid TTL values above n. Default is 255, the theoretical limit.

    -maxprobes n

Sets the maximum number of probes to use before the software stops, even if it has not found the exact number of hops to the destination. The default is 50.

    -max-wait n

Sets the maximum waiting time (in seconds) before the software stops. Default is 30.

    -no-parallel
    -parallel n

Makes the process employ a maximum of n parallel probes. The default value is 1. The -no-parallel option is equal to -parallel 1.

    -probe-pacing s

When sending parallel probes, by default they are sent right after each other. However, with the probe-pacing option you can specify the number of microseconds to wait before sending another probe.

    -algorithm a

Select the probing algorithm: sequential, reversesequential, random, or binarysearch. The default is binarysearch.

    -readjust
    -no-readjust

Sets the algorithms to adjust random or sequential ranges based on what is learned during the probing process, and then pick future values only from the remaining possible range. For instance, a reply from the destination implies that the number of hops is not higher than the TTL in the probe that provoked that reply. And per Tero Kivinen's observation, a reply with the remaining TTL (as it arrives) set to x lets us conclude that the number of hops is at most 255-x, because when the reply was sent, the TTL value was at most 255.

    -likely-candidates
    -no-likely-candidates

Sets the binary search to start either from the middle of the theoretical range (TTL 128) or from a value that has been determined to be a likely path length for general Internet destinations. A good quess will speed up the search process. The default is that the good guesses are in use.

    -retransmit-priority
    -new-probe-priority

This setting controls whether probes that do not get answered should be retransmitted when the alternative is to send new probes instead. If a new probe can be sent that would potentially bring useful information, then it is sent with the same retransmission parameters (exponential back-off timeout etc) than the retransmission would have been sent as. The default is preference of new probes over retransmission.

    -probabilistic-distribution
    -plain-distribution

This setting controls how binary search and other values are selected for probing. In a plain distribution, any value is equally likely. For instance, any hop count between 1 and 255 would be equally likely. In the probabilistic model, built-in knowledge of likely hop counts steers the choice to the more likely values. For instance, hop counts beyond 50 are rarely seen in the Internet, and for the most popular destinations, values in the range of up to 20 hops are more likely. The default setting is to use probabilistic distribution.

    -maxtries n

Set the maximum number of tries for one hop before giving up if there no replies or even errors coming back. The default is 3.

    -interface i

Set the interface. The default is eth0.

    -startttl n

Start the probing process was a given TTL value. By default, for the sequential algorithm, the start value is 1. For the reverse sequential algorithm, the start value is 255.

# Installation

The easiest installation method is to retrieve the software from GitHub:

    git clone https://github.com/jariarkko/hopping.git
    sudo make all install

# Things to do

The software is being worked on. In particular, it doesn't deal with parallel probing very well yet, and at the moment it also completely fails when a probe times out. Sadly, the software only implements IPv4 at the moment, so IPv6 needs to be added, hopefully doing this soon. The software is based on ICMP at the moment, but a UDP mode would be very useful for networks that do not pass ICMP messages through. Further algorithms and improvements are also worked on.
