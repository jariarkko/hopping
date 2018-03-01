#!/bin/bash

#
# Testing different algorithms against each other in the hopping
# program
#

DESTINATIONSFILE="hopping-test-destinations.txt"
TMPOUTPUT=/tmp/hopping-test.out
RESULTFILE=/tmp/hopping-test-results.txt

rm -f $TMPOUTPUT 2> /dev/null
rm -f $RESULTFILE 2> /dev/null
touch $RESULTFILE

echo "# HOPS	SEQ	RSEQ	RND	BIN	BIN+LC" >> $RESULTFILE

for item in `cat $DESTINATIONSFILE`
do
    count=`echo $item | cut -f1 -d:`
    destination=`echo $item | cut -f2 -d:`

    echo ''
    echo '**** Running tests for hopcount '$count
    echo ''

    echo -n "$count	" >> $RESULTFILE
    para=1
    for choice in sequential reversesequential random binarysearch binarysearch-likelycandidate
    do
	if [ "$choice" = "binarysearch-likelycandidate" ]
	then
	    algo=binarysearch
	    options="-likely-candidates"
	else
	    algo=$choice
	    options="-no-likely-candidates"
	fi
	cmd="./hopping -quiet -machine-readable $options -algorithm $algo -parallel $para $destination"
	# echo "$cmd ..." 2> /dev/stderr	
	if $cmd > $TMPOUTPUT
	then
	    hopscount=`head -1 $TMPOUTPUT | cut -f1 -d:`
	    probecount=`tail -1 $TMPOUTPUT`
	    if [ "x$hopscount" != x"$count" ]
	    then
		echo "Warning: for $destination with algorithm $algo, hop counts differ $hopscount vs. $count -- continuing" 2> /dev/stderr
		result="fail"
	    else
		if [ "x$hopscount" = "x" -o "x$probecount" = "x" ]
		then
		    echo "Failed for $destination with algorithm $algo -- exit"
		    exit 1;
		else
		    result=$probecount
		fi
	    fi
	else
	    result="fail"
	fi
	echo -n "$result	" >> $RESULTFILE
    done
    echo "" >> $RESULTFILE
done

echo ''
echo '**** Results'
echo ''

cat $RESULTFILE

echo ''
echo '**** Constructing Gnuplot files'
echo ''

cp $RESULTFILE hopping-results-full.txt
sed 's/fail/50/g' $RESULTFILE > hopping-results-data.txt

echo "set grid" > hopping-results-gnuplot.txt
echo "set title 'HOP COUNT ALGORITHMS'" > hopping-results-gnuplot.txt
echo "set yrange [0:50]" > hopping-results-gnuplot.txt
echo "set xlabel 'Hops'" > hopping-results-gnuplot.txt
echo "set ylabel 'Probes'" > hopping-results-gnuplot.txt
echo "unset label" > hopping-results-gnuplot.txt
echo "plot 'hopping-results-data.txt' u 1:2 w lp t 'Sequential', 'hopping-results-data.txt' u 1:3 w lp t 'Reverse-Sequential', 'hopping-results-data.txt' u 1:4 w lp t 'Random', 'hopping-results-data.txt' u 1:5 w lp t 'Binary-Search', 'hopping-results-data.txt' u 1:6 w lp t 'Binary-Search /w Likely'" > hopping-results-gnuplot.txt

echo ''
echo '**** Running gnuplot'
echo ''

gnuplot < 
