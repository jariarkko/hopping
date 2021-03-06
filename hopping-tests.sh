#!/bin/bash

#
# Testing different algorithms against each other in the hopping
# program
#

DESTINATIONSFILE="hopping-test-destinations.txt"
TMPOUTPUT=/tmp/hopping-test.out

for para in 16 8 4 2 1
do
    
    RESULTFILE="/tmp/hopping-test-results-$para.txt"
    
    rm -f $TMPOUTPUT 2> /dev/null
    rm -f $RESULTFILE 2> /dev/null
    touch $RESULTFILE
    
    echo "# HOPS	SEQ	RND	BIN	BIN+LC	BIN+LC+PD" >> $RESULTFILE

    for item in `cat $DESTINATIONSFILE`
    do
	count=`echo $item | cut -f1 -d:`
	destination=`echo $item | cut -f2 -d:`
	
	echo -n ''
	echo '**** Running tests for '$para'-parallel hopcount '$count
	echo -n ''
	
	echo -n "$count	" >> $RESULTFILE

	# reversesequential
	for choice in sequential random binarysearch binarysearch-likelycandidate binarysearch-likelycandidate-probability-distribution
	do
	    if [ "$choice" = "binarysearch-likelycandidate" ]
	    then
		algo=binarysearch
		options="-likely-candidates -plain-distribution"
	    else
		if [ "$choice" = binarysearch-likelycandidate-probability-distribution ]
		then
		    algo=binarysearch
		    options="-likely-candidates -probabilistic-distribution"
		else
		    algo=$choice
		    options="-no-likely-candidates -plain-distribution"
		fi
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
    echo '**** Results for '$para'-parallel'
    echo ''
    
    cat $RESULTFILE
    
    echo ''
    echo '**** Constructing Gnuplot files for '$para'-parallel'
    echo ''

    FULLFILE=hopping-results-full-$para.txt
    DATAFILE=hopping-results-data-$para.txt
    CMDFILE=hopping-results-gnuplot-$para.txt
    PICFILE=hopping-results-gnuplot-$para.png
    
    cp $RESULTFILE $FULLFILE
    sed 's/fail/40/g' $RESULTFILE > $DATAFILE
    
    echo "set terminal png" > $CMDFILE
    echo "set terminal png size 1920,1080 font 'Helvetica,14'" >> $CMDFILE
    echo "set grid" >> $CMDFILE
    echo "set title 'HOP COUNT ALGORITHMS, "$para" PARALLEL PROBES'" >> $CMDFILE
    echo "set yrange [0:40]" >> $CMDFILE
    echo "set xlabel 'Hops'" >> $CMDFILE
    echo "set ylabel 'Probes'" >> $CMDFILE
    echo "unset label" >> $CMDFILE
    echo "plot '$DATAFILE' u 1:2 w lp lw 2 t 'SEQ', '$DATAFILE' u 1:3 w lp lw 2 t 'RND', '$DATAFILE' u 1:4 w lp lw 2 t 'BIN', '$DATAFILE' u 1:5 w lp lw 2 t 'BINL', '$DATAFILE' u 1:6 w lp lw 2 t 'BINP'" >> $CMDFILE
    
    echo ''
    echo '**** Running gnuplot for '$para'-parallel'
    echo ''
    
    gnuplot < $CMDFILE > $PICFILE
    
done
