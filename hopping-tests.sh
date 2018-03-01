#!/bin/bash

#
# Testing different algorithms against each other in the hopping
# program
#

DESTINATIONSFILE="hopping-test-destinations.txt"
TMPOUTPUT=/tmp/hopping-test.out
RESULTFILE=/tmp/hopping-test-results.txt

rm $TMPOUTPUT
rm $RESULTFILE
touch $RESULTFILE

echo "#	HOPS	SEQ	RSEQ	RND	BINS"

for item in `cat $DESTINATIONSFILE`
do
    count=`echo $item | cut -f1 -d:`
    destination=`echo $item | cut -f2 -d:`
    echo "$count	" >> $RESULTFILE
    para=4
    for algo in sequential reversesequential random binarysearch
    do
	if ./hopping -quiet -algorithm $algo -parallel $para $destination > $TMPOUTPUT
	then
	    hopscount=`grep "hops away" $TMPOUTPUT | cut -f4 -d" " | tr -d abcdefghijklmopqrstuvwxyzABCDEFGHIJKLMOPQRSTUVWXYZ`
	    probecount=`grep "probes sent" $TMPOUTPUT | cut -f1 -d" " | tr -d abcdefghijklmopqrstuvwxyzABCDEFGHIJKLMOPQRSTUVWXYZ`
	    if [ "x$hopscount" != x"$count" ]
	    then
		echo "Failed for $destination with algorithm $algo, hop counts differ $hopscount vs. $count-- exit"
		exit 1;
	    else
		if [ "x$hopscount" = "x" -o "x$probecount" = "x" ]
		then
		    echo "Failed for $destination with algorithm $algo -- exit"
		    exit 1;
		else
		    result=$probecount
		fi
	    else
		result="fail"
	    fi
	    echo -n "$result	" >> $RESULTFILE
	fi
    done
    echo "" >> $RESULTFILE
    exit 0
done

cat $RESULTFILE
