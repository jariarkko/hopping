
//
// ----------------------- HOPPING --------------------------------
//
//                An Efficient Hop Counter
//
//                      by Jari Arkko
//
//
//           All rights reserved for the moment
//            (working on open sourcing this)
//

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <errno.h>


//
// Constants for the protocols formats -------------------------------
//

#define HOPPING_IP4_HDRLEN			20
#define HOPPING_ICMP4_HDRLEN			 8
#define HOPPING_ICMP_ECHOREPLY			 0
#define HOPPING_ICMP_DEST_UNREACH		 3
#define HOPPING_ICMP_ECHO			 8
#define HOPPING_ICMP_TIME_EXCEEDED		11


//
// Types -------------------------------------------------------------
//

typedef uint16_t hopping_idtype;

enum hopping_algorithms {
  hopping_algorithms_random,
  hopping_algorithms_sequential,
  hopping_algorithms_reversesequential,
  hopping_algorithms_binarysearch
};

enum hopping_responseType {
  hopping_responseType_stillWaiting,
  hopping_responseType_echoResponse,
  hopping_responseType_destinationUnreachable,
  hopping_responseType_timeExceeded,
  hopping_responseType_noResponse
};

struct hopping_probe {
  int used;
  hopping_idtype id;
  unsigned char hops;
  struct hopping_probe* previousTransmission;
  struct hopping_probe* nextRetransmission;
  unsigned int probeLength;
  struct timeval sentTime;
  struct timeval initialTimeout;
  int responded;
  unsigned int duplicateResponses;
  unsigned int responseLength;
  struct timeval responseTime;
  unsigned long delayUSecs;
  enum hopping_responseType responseType;
};

typedef int (*hopping_ttl_test_function)(unsigned char ttl);

//
// Constants ------------------------------------------------------------
//

#define hopping_algorithms_string	\
        "random, sequential, reversesequential, or binarysearch"

#define HOPPING_MAX_PROBES			        256
#define HOPPING_POLL_FREQUENCY				10
#define HOPPING_POLL_SLEEP_US				((1000 * 1000) /              \
                                       			  HOPPING_POLL_FREQUENCY)
#define HOPPING_INITIAL_RETRANSMISSION_TIMEOUT_US	(500 * 1000)
#define HOPPING_MAX_RETRANSMISSION_TIMEOUT_US		(20 * 1000 * 1000)
#define HOPPING_RETRANSMISSION_BACKOFF_FACTOR		2
#define HOPPING_TYPICAL_INTERNET_HOP_COUNT		12
#define HOPPING_TYPICAL_INTERNET_MAX_HOP_COUNT		24
#define HOPPING_N_TYPICAL_HOP_COUNT_TRIES		4

//
// Variables ------------------------------------------------------------
//

const char* testDestination = "www.google.com";
struct sockaddr_in testDestinationAddress;
const char* interface = "eth0";
static int debug = 0;
static int progress = 1;
static int progressDetailed = 0;
static int conclusion = 1;
static int briefStatistics = 1;
static int fullStatistics = 0;
static int machineReadable = 0;
static unsigned int startTtl = 1;
static unsigned int maxTtl = 255;
static unsigned int maxProbes = 30;
static unsigned int maxTries = 3;
static unsigned int parallel = 1;
static unsigned int likelyCandidates = 1;
static unsigned int bucket = 0;
static int interrupt = 0;
static unsigned int icmpDataLength = 0;
static enum hopping_algorithms algorithm = hopping_algorithms_binarysearch;
static int readjust = 1;
static struct hopping_probe probes[HOPPING_MAX_PROBES];
static unsigned int probesSent = 0;
static unsigned char currentTtl = 1;
static int seenprogressreport = 0;
static int lastprogressreportwassentpacket = 0;
static unsigned char hopsMinInclusive = 1;
static unsigned char hopsMaxInclusive = 255;


//
// Prototype definitions of functions ------------------------------------
//

static void
hopping_reportBriefConclusion(void);
static void
hopping_sendprobe(int sd,
		  struct sockaddr_in* destinationAddress,
		  struct sockaddr_in* sourceAddress,
		  unsigned int expectedLen,
		  struct hopping_probe* probe);
static void
hopping_getcurrenttime(struct timeval* result);
static void
fatalf(const char* format, ...);
static unsigned int
hopping_responses();
static unsigned char
hopping_bestbinarysearchvalue(unsigned char from,
			      unsigned char to,
			      hopping_ttl_test_function suitableTestFunction,
			      unsigned int numberOfTests);
static unsigned char
hopping_bestinitialotherguess(unsigned char from,
			      unsigned char to,
			      hopping_ttl_test_function suitableTestFunction,
			      unsigned int numberOfTests);

//
// Some helper macros ----------------------------------------------------
//

#define hopping_assert(cond)	if (!(cond)) {                             \
                                  fatalf("Assertion failed on %s line %u", \
                                         __FILE__, __LINE__);		   \
                                }
#define hopping_min(a,b)	((a) < (b) ? (a) : (b))
#define hopping_max(a,b)	((a) > (b) ? (a) : (b))


//
// Functions -------------------------------------------------------------
//

//
// Debug helper function
//

static void
debugf(const char* format, ...) {

  hopping_assert(format != 0);
  
  if (debug) {

    va_list args;

    printf("hopping: debug: ");
    va_start (args, format);
    vprintf(format, args);
    va_end (args);
    printf("\n");
    
  }
  
}

//
// Display a fatal error
//

static void
fatalf(const char* format, ...) {
  
  va_list args;
  
  hopping_assert(format != 0);
  
  fprintf(stderr,"hopping: error: ");
  va_start (args, format);
  vfprintf(stderr, format, args);
  va_end (args);
  fprintf(stderr," -- exit\n");
  
  exit(1);
}

//
// Display a fatal error a la perror
//

static void
fatalp(const char* message) {
  
  const char* string = strerror(errno);
  hopping_assert(message != 0);
  fatalf("system: %s", string);
  
}

//
// Algorithm name to string
//

static const char*
hopping_algorithm2name(enum hopping_algorithms algo) {
  switch (algo) {
  case hopping_algorithms_random: return("random");
  case hopping_algorithms_sequential: return("sequential");
  case hopping_algorithms_reversesequential: return("reversesequential");
  case hopping_algorithms_binarysearch: return("binarysearch");
  default:
    fatalf("invalid internal algorithm setting");
    return("");
  }
}

//
// String processing: fill a buffer with string (cut/repeated as needed
// to fill the expected length)
//

static void
hopping_fillwithstring(char* buffer,
		       const char* string,
		       unsigned char bufferSize) {
  
  const char* stringPointer = string;

  hopping_assert(buffer != 0);
  hopping_assert(string != 0);
  
  while (bufferSize > 0) {
    *buffer = *stringPointer;
    buffer++;
    bufferSize--;
    if (*stringPointer != '\0') stringPointer++;
    if (*stringPointer == '\0') stringPointer = string;
  }
  
}

static unsigned long
hopping_timeisless(struct timeval* earlier,
		   struct timeval* later) {

  hopping_assert(earlier != 0);
  hopping_assert(later != 0);
  
  if (earlier->tv_sec < later->tv_sec) return(1);
  else if (earlier->tv_sec > later->tv_sec) return(0);
  else if (earlier->tv_usec < later->tv_usec) return(1);
  else return(0);
}

static unsigned long
hopping_timediffinusecs(struct timeval* later,
			struct timeval* earlier) {
  
  hopping_assert(earlier != 0);
  hopping_assert(later != 0);
  
  if (later->tv_sec < earlier->tv_sec) {
    fatalf("expected later time to be greater, second go back %uls", earlier->tv_sec - later->tv_sec);
  }
  if (later->tv_sec == earlier->tv_sec) {
    if (later->tv_usec < earlier->tv_usec) {
      fatalf("expected later time to be greater, microsecond go back %uls", earlier->tv_usec - later->tv_usec);
    }
    return(later->tv_usec - earlier->tv_usec);
  } else {
    unsigned long result = 1000 * 1000 * (later->tv_sec - earlier->tv_sec);
    result += (1000*1000) - earlier->tv_usec;
    result += later->tv_usec;
    return(result);
  }
}

static void
hopping_timeadd(struct timeval* base,
		unsigned long us,
		struct timeval* result) {
  unsigned long totalUs = base->tv_usec + us;
  hopping_assert(result != 0);
  result->tv_sec = base->tv_sec + totalUs / (1000 * 1000);
  result->tv_usec = base->tv_usec + totalUs % (1000 * 1000);
}

//
// Convert an IPv4 address to string
//

static const char*
hopping_addrtostring(struct in_addr* addr) {
  hopping_assert(addr != 0);
  return(inet_ntoa(*addr));
}

//
// Get current time
//

static void
hopping_getcurrenttime(struct timeval* result) {
  hopping_assert(result != 0);
  if (gettimeofday(result, 0) < 0) {
    fatalp("cannot determine current time via gettimeofday");
  }
}

//
// Add a new probe entry
//

static struct hopping_probe*
hopping_newprobe(hopping_idtype id,
		 unsigned char hops,
		 unsigned int probeLength,
		 struct hopping_probe* previousProbe) {
  
  struct hopping_probe* probe = &probes[id];
  hopping_assert(id < HOPPING_MAX_PROBES);
  if (probe->used) {
    fatalf("cannot allocate a new probe for id %u", (unsigned int)id);
    return(0);
  }

  memset(probe,0,sizeof(*probe));
  
  probe->used = 1;
  probe->id = id;
  probe->hops = hops;
  probe->probeLength = probeLength;
  probe->responded = 0;
  probe->duplicateResponses = 0;
  probe->responseType = hopping_responseType_stillWaiting;
  
  //
  // Set the current time as the time the probe was sent
  // (although technically it hasn't been sent yet... but in
  // few microseconds it will as soon as this function exits).
  //

  hopping_getcurrenttime(&probe->sentTime);

  //
  // Figure out if this is a retransmission of a previous probe.
  
  probe->nextRetransmission = 0;
  if (previousProbe == 0) {
    probe->previousTransmission = 0;
    hopping_timeadd(&probe->sentTime,
			HOPPING_INITIAL_RETRANSMISSION_TIMEOUT_US,
			&probe->initialTimeout);
  } else {
    unsigned long prevTimeout =
      hopping_timediffinusecs(&previousProbe->initialTimeout,
				  &previousProbe->sentTime);
    unsigned long newTimeout =
      prevTimeout * HOPPING_RETRANSMISSION_BACKOFF_FACTOR;
    if (newTimeout > HOPPING_MAX_RETRANSMISSION_TIMEOUT_US)
      newTimeout = HOPPING_MAX_RETRANSMISSION_TIMEOUT_US;
    probe->previousTransmission = previousProbe;
    previousProbe->nextRetransmission = probe;
    hopping_timeadd(&probe->sentTime,
			newTimeout,
			&probe->initialTimeout);
  }
  
  debugf("registered a probe for id %u, ttl %u", id, hops);
  
  probesSent++;
  if (bucket > 0) bucket--;
  return(probe);
}

//
// Find a probe based on TTL
//

static struct hopping_probe*
hopping_findprobe_basedonttl(unsigned char ttl) {

  hopping_idtype id;

  //
  // Look for a suitable probe in the probe table
  //
  
  for (id = 0; id < HOPPING_MAX_PROBES; id++) {
    struct hopping_probe* probe = &probes[id];
    if (probe->used &&
	probe->hops == ttl) {
      debugf("found a probe for TTL %u", ttl);
      return(probe);
    }
  }

  //
  // Did not find one
  //

  debugf("cannot find a probe for TTL %u", ttl);
  return(0);
}


//
// Find a probe based on the ID
//

static struct hopping_probe*
hopping_findprobe(hopping_idtype id) {
  
  struct hopping_probe* probe = &probes[id];
  
  if (!probe->used) {
    debugf("have not sent a probe with id %u", (unsigned int)id);
    return(0);
  } else if (probe->responded) {
    debugf("have already seen a response to the probe with id %u", (unsigned int)id);
    return(0);
  } else {
    return(probe);
  }
  
}

//
// Check if there is a probe based on TTL
//

static int
hopping_thereisprobe_ttl(unsigned char ttl) {
  int answer = (hopping_findprobe_basedonttl(ttl) != 0);
  debugf("hopping_thereisprobe_ttl %u answer is %u", answer);
  return(answer);
}

//
// Check if there is no probe based on TTL
//

static int
hopping_thereisnoprobe_ttl(unsigned char ttl) {
  int answer = !hopping_thereisprobe_ttl(ttl);
  debugf("hopping_thereisnoprobe_ttl %u answer is %u", ttl, answer);
  return(answer);
}

//
// Count how many retranmissions this TTL has seen
//

static unsigned int
hopping_retries(struct hopping_probe* probe) {
  hopping_assert(probe != 0);
  if (probe->previousTransmission != 0) {
    return(1+hopping_retries(probe->previousTransmission));
  } else {
    return(1);
  }
}

//
// Count how many probes we have NOT yet sent on a given range
//

static unsigned int
hopping_countprobes_notsentinrange(unsigned char fromttl,
				   unsigned char tottl) {

  unsigned int index = (unsigned int)fromttl;
  unsigned int count = 0;
  
  for (index = 0; index < (unsigned int)tottl; index++) {
    if (hopping_thereisnoprobe_ttl((unsigned char)index)) {
      count++;
    }
  }
  
  return(count);
}

//
// Register the reception of a response (ECHO, UNREACHABLE or TIME
// EXCEEDED) to a probe.
//

static void
hopping_registerResponse(enum hopping_responseType type,
			 hopping_idtype id,
			 unsigned char responseTtl,
			 unsigned int packetLength,
			 struct hopping_probe** responseToProbe) {

  //
  // See if we can find the probe that this is a response to
  //
  
  struct hopping_probe* probe = hopping_findprobe(id);

  hopping_assert(responseToProbe != 0);
  
  if (probe == 0) {
    debugf("cannot find the probe that response id %u was a response to", id);
    *responseToProbe = 0;
    return;
  }
  
  //
  // Look at the state of the probe
  //
  
  if (probe->responded) {
    debugf("we have already seen a response to probe id %u", id);
    *responseToProbe = probe;
    probe->duplicateResponses++;
    return;
  }
  
  //
  // This is new. Update the probe data
  //
  
  debugf("this is a new valid response to probe id %u", id);
  probe->responded = 1;
  probe->responseLength = packetLength;
  hopping_getcurrenttime(&probe->responseTime);
  probe->delayUSecs = hopping_timediffinusecs(&probe->responseTime,
						  &probe->sentTime);
  debugf("probe delay was %.3f ms", probe->delayUSecs / 1000.0);
  probe->responseType = type;
  
  //
  // Update our conclusions about the destination
  //
  
  if (type == hopping_responseType_echoResponse) {
    
    hopsMaxInclusive = hopping_min(hopsMaxInclusive, probe->hops);
    debugf("echo reply means hops is at most %u", hopsMaxInclusive);
    
    //
    // Additional conclusions can be drawn as suggested
    // by Tero Kivinen: if a packet is received with TTL n,
    // then it TTL cannot be larger than 255-n, because the
    // packet must have been sent with a TTL of at most
    // 255.
    //

    hopsMaxInclusive = hopping_min(hopsMaxInclusive,
				   255 - responseTtl);
    debugf("echo reply TTL was %u so hops must be at most %u",
	   responseTtl, hopsMaxInclusive);
    
    //
    // TODO: one might also optimistically assume that
    // sender used default TTL of 64, in which case we
    // can pretty much guess what the TTL is.
    //
    
  }
  if (type == hopping_responseType_timeExceeded && probe->hops < 255) {
    hopsMinInclusive = hopping_max(hopsMinInclusive,probe->hops + 1);
    debugf("time exceeded means hops is at least %u", hopsMinInclusive);
  }
  
  //
  // Update the task counters
  //
  
  bucket++;
  if (bucket > parallel) bucket = parallel;
  
  //
  // Return, and set output parameters
  //
  
  *responseToProbe = probe;
}

//
// Allocate new identifiers for the different probes
//

static hopping_idtype
hopping_getnewid(unsigned char hops) {
  
  static unsigned int nextId = 0;
  unsigned int id;
  
  do {
    
    id = nextId++;
    struct hopping_probe* probe = &probes[id];
    if (probe->used) continue;
    else return(id);
    
  } while (id <= 65535 && id +1 < HOPPING_MAX_PROBES);
  
  fatalf("cannot find a new identifier for %u hops", hops);
  return(0);
}

//
// Finding out an interface index for a named interface
//

static void
hopping_getifindex(const char* interface,
		   int* ifIndex,
		   struct ifreq* ifrp,
		   struct sockaddr_in *addr) {
  
  struct ifreq ifr;
  int sd;

  hopping_assert(interface != 0);
  hopping_assert(ifIndex != 0);
  hopping_assert(addr != 0);
  
  //
  // Get a raw socket
  //
  
  if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    fatalp("socket() failed to get socket descriptor for using ioctl()");
  }
  
  //
  // Find interface index
  //
  
  memset (&ifr,0,sizeof (ifr));
  strncpy(ifr.ifr_name, interface, sizeof (ifr.ifr_name));
  if (ioctl (sd, SIOCGIFINDEX, &ifr) < 0) {
    fatalp("ioctl() failed to find interface");
  }
  *ifIndex = ifr.ifr_ifindex;
  *ifrp = ifr;
  
  //
  // Find own source address
  //
  
  memset (&ifr,0,sizeof (ifr));
  strncpy(ifr.ifr_name, interface, sizeof (ifr.ifr_name));
  if (ioctl(sd,SIOCGIFADDR,&ifr)==-1) {
    fatalp("ioctl() failed to find interface address");
  }
  *addr = *(struct sockaddr_in*)&ifr.ifr_addr;
  
  //
  // Cleanup and return
  //

  close (sd);
}

static void
hopping_getdestinationaddress(const char* destination,
			      struct sockaddr_in* address) {
  
  struct addrinfo hints, *res;
  struct sockaddr_in *addr;
  int rcode;

  hopping_assert(destination != 0);
  hopping_assert(address != 0);
  
  memset(&hints,0,sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;
  
  if ((rcode = getaddrinfo(destination, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "hopping: cannot resolve address %s: %s\n", destination, gai_strerror (rcode));
    exit(1);
  }
  *address = *(struct sockaddr_in*)res->ai_addr;
}

//
// Mapping addresses to strings (n.n.n.n or h:h:...:h)
//

static const char*
hopping_iptostring(struct sockaddr_in* in) {
  char* result = (char*)malloc(INET_ADDRSTRLEN+1);
  memset(result,0,INET_ADDRSTRLEN+1);
  if (inet_ntop (AF_INET, (void*)&in->sin_addr, result, INET_ADDRSTRLEN) == NULL) {
    fatalf("inet_ntop() failed");
  }
}

//
// Checksum per RFC 1071
//

static uint16_t
hopping_checksum(uint16_t* data,
		     int length)
{
  register uint32_t sum = 0;
  int count = length;

  hopping_assert(data != 0);
  
  while (count > 1) {
    sum += *(data++);
    count -= 2;
  }
  
  if (count > 0) {
    sum += *(uint8_t*)data;
  }
  
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  
  return(~sum);
}

//
// Construct an ICMPv4 packet
//

static void
hopping_constructicmp4packet(struct sockaddr_in* source,
			     struct sockaddr_in* destination,
			     hopping_idtype id,
			     unsigned char ttl,
			     unsigned int dataLength,
			     char** resultPacket,
			     unsigned int* resultPacketLength) {
  
  static const char* message = "archtester";
  static char data[IP_MAXPACKET];
  static char packet[IP_MAXPACKET];
  struct icmp icmphdr;
  struct ip iphdr;
  unsigned int icmpLength;
  unsigned int packetLength;

  //
  // Make some checks
  //

  hopping_assert(source != 0);
  hopping_assert(destination != 0);
  hopping_assert(resultPacket != 0);
  hopping_assert(resultPacketLength != 0);
  
  if (HOPPING_IP4_HDRLEN + HOPPING_ICMP4_HDRLEN + dataLength > IP_MAXPACKET) {
    fatalf("requesting to make a too long IP packet for data length %u", dataLength);
  }
  
  //
  // Fill in ICMP parts
  //
  
  icmphdr.icmp_type = HOPPING_ICMP_ECHO;
  icmphdr.icmp_code = 0;
  icmphdr.icmp_id = id;
  icmphdr.icmp_seq = (uint16_t)(probesSent & 0xFFFF);
  icmphdr.icmp_cksum = 0;
  hopping_fillwithstring(data,message,dataLength);
  icmpLength = HOPPING_ICMP4_HDRLEN + dataLength;
  memcpy(packet + HOPPING_IP4_HDRLEN,&icmphdr,HOPPING_ICMP4_HDRLEN);
  memcpy(packet + HOPPING_IP4_HDRLEN + HOPPING_ICMP4_HDRLEN,data,dataLength);
  icmphdr.icmp_cksum = hopping_checksum((uint16_t*)(packet + HOPPING_IP4_HDRLEN), icmpLength);
  memcpy(packet + HOPPING_IP4_HDRLEN,&icmphdr,HOPPING_ICMP4_HDRLEN);
  
  //
  // Fill in the IPv4 header
  //
  
  iphdr.ip_hl = 5;
  iphdr.ip_v = 4;
  iphdr.ip_tos = 0;
  packetLength = HOPPING_IP4_HDRLEN + icmpLength;
  iphdr.ip_len = htons (packetLength);
  iphdr.ip_id = id;
  iphdr.ip_off = 0;
  iphdr.ip_ttl = ttl;
  iphdr.ip_p = IPPROTO_ICMP;
  iphdr.ip_src = source->sin_addr;
  iphdr.ip_dst = destination->sin_addr;
  iphdr.ip_sum = 0;
  iphdr.ip_sum = hopping_checksum((uint16_t*)&iphdr,HOPPING_IP4_HDRLEN);
  memcpy (packet, &iphdr, HOPPING_IP4_HDRLEN);

  //
  // Debugs
  //
  
  debugf("constructed a packet of %u bytes, ttl = %u", packetLength, ttl);
  
  //
  // Return the packet
  //
  
  *resultPacket = packet;
  *resultPacketLength = packetLength;
}

//
// Send a plain IP packet to raw socket
//

static void
hopping_sendpacket(int sd,
		   char* packet,
		   unsigned int packetLength,
		   struct sockaddr* addr,
		   size_t addrLength)  {

  hopping_assert(packet != 0);
  hopping_assert(addr != 0);
  
  if (sendto (sd, packet, packetLength, 0, addr, sizeof (struct sockaddr)) < 0) {
    fatalp("sendto() failed");
  }
  
}

//
// Receive a packet from the raw socket
//

static int
hopping_receivepacket(int sd,
		      char** result,
		      int sleep) {
  
  static char packet[IP_MAXPACKET];
  struct timeval timeout;
  struct sockaddr from;
  socklen_t fromlen;
  fd_set reads;
  int selres;
  int bytes;
  
  debugf("waiting for responses");
  hopping_assert(result != 0);
  hopping_assert(sleep == 0 || sleep == 1);
  
  //
  // Perform a select call to wait for
  // either a timeout or something on the
  // raw socket
  //
  
  timeout.tv_sec = 0;
  if (sleep)
    timeout.tv_usec = HOPPING_POLL_SLEEP_US;
  else
    timeout.tv_usec = 0;
  FD_ZERO(&reads);
  FD_SET(sd,&reads);
  selres = select(1, &reads, 0, 0, &timeout);
  
  //
  // We have possibly something to receive
  // (or timeout, in any case, check if there
  // is something to receive).
  //
  
  bytes = recvfrom(sd,
		   packet,
		   sizeof(packet),
		   MSG_DONTWAIT,
		   (struct sockaddr*)&from,
		   &fromlen);
  
  if (bytes < 0 && errno != EAGAIN) {
    
    debugf("bytes %u, errno %u", bytes, errno);
    fatalp("socket() failed to read from the raw socket");
    
  } else if (bytes > 0) {
  
    *result = packet;
    return(bytes);
    
  } else {

    debugf("nothing to read");
    return(0);
    
  }
}

//
// IP & ICMP packet validation
//

static int
hopping_validatepacket(char* receivedPacket,
		       int receivedPacketLength,
		       enum hopping_responseType* responseType,
		       hopping_idtype* responseId,
		       unsigned char* responseTtl,
		       struct ip* responseToIpHdr,
		       struct icmp* responseToIcmpHdr) {
  
  struct ip iphdr;
  struct icmp icmphdr;

  //
  // Check parameters
  //

  hopping_assert(receivedPacket != 0);
  hopping_assert(responseType != 0);
  hopping_assert(responseId != 0);
  hopping_assert(responseTtl != 0);
  
  //
  // Validate IP4 header
  //
  
  if (receivedPacketLength < HOPPING_IP4_HDRLEN) return(0);
  memcpy(&iphdr,receivedPacket,HOPPING_IP4_HDRLEN);
  if (iphdr.ip_v != 4) return(0);
  if (ntohs(iphdr.ip_len) < receivedPacketLength) return(0);
  if (iphdr.ip_off != 0) return(0);
  if (iphdr.ip_p != IPPROTO_ICMP) return(0);

  //
  // What was the TTL of the received packet?
  // And for some reason, we're getting one higher
  // TTL than the actual value should be...
  //
  
  *responseTtl = iphdr.ip_ttl;
  if (*responseTtl > 0) (*responseTtl)--;
  
  //
  // IP checksum
  //
  
  // TODO: check iphdr.ip_sum ...
  
  //
  // Validate ICMP4 header
  //
  
  if (receivedPacketLength < HOPPING_IP4_HDRLEN + HOPPING_ICMP4_HDRLEN) return(0);
  memcpy(&icmphdr,&receivedPacket[HOPPING_IP4_HDRLEN],HOPPING_ICMP4_HDRLEN);
  *responseId = icmphdr.icmp_id;
  
  // TODO: check icmphdr.icmp_sum ...

  switch (icmphdr.icmp_type) {

  case HOPPING_ICMP_ECHOREPLY:
    *responseType = hopping_responseType_echoResponse;
    debugf("ECHO RESPONSE from %s", hopping_addrtostring(&iphdr.ip_src));
    break;

  case HOPPING_ICMP_TIME_EXCEEDED:
    if (icmphdr.icmp_code != 0) {
      debugf("ICMP code in TIME EXCEEDED is not 0");
      return(0);
    }
    if (ntohs(iphdr.ip_len) <
	HOPPING_IP4_HDRLEN + HOPPING_ICMP4_HDRLEN +
	HOPPING_IP4_HDRLEN + HOPPING_ICMP4_HDRLEN) {
      debugf("ICMP error does not include enough of the original packet", ntohs(iphdr.ip_len));
      return(0);
    }
    memcpy(responseToIpHdr,
	   &receivedPacket[HOPPING_IP4_HDRLEN+HOPPING_ICMP4_HDRLEN],
	   HOPPING_IP4_HDRLEN);
    memcpy(responseToIcmpHdr,
	   &receivedPacket[HOPPING_IP4_HDRLEN+HOPPING_ICMP4_HDRLEN+HOPPING_IP4_HDRLEN],
	   HOPPING_ICMP4_HDRLEN);
    *responseId = responseToIcmpHdr->icmp_id;
    debugf("inner header as seen by hopping_validatepacket:");
    debugf("  inner ip proto = %u", responseToIpHdr->ip_p);
    debugf("  inner ip len = %u", ntohs(responseToIpHdr->ip_len));
    debugf("  inner ip id = %u", responseToIpHdr->ip_id);
    debugf("  inner ip offset = %u", responseToIpHdr->ip_off);
    debugf("  inner icmp type = %u", responseToIcmpHdr->icmp_type);
    debugf("  inner icmp code = %u", responseToIcmpHdr->icmp_code);
    debugf("using inner id %u in ICMP error", *responseId);
    if (responseToIpHdr->ip_p != IPPROTO_ICMP &&
	responseToIcmpHdr->icmp_type != HOPPING_ICMP_ECHO) {
      debugf("ICMP error includes some other packet than ICMP ECHO proto = %u icmp code = %u",
	     responseToIpHdr->ip_p,
	     responseToIcmpHdr->icmp_type);
      return(0);
    }
    *responseType = hopping_responseType_timeExceeded;
    debugf("TIME EXCEEDED from %s", hopping_addrtostring(&iphdr.ip_src));
    break;

  case HOPPING_ICMP_DEST_UNREACH:
    if (ntohs(iphdr.ip_len) <
	HOPPING_IP4_HDRLEN + HOPPING_ICMP4_HDRLEN +
	HOPPING_IP4_HDRLEN + HOPPING_ICMP4_HDRLEN) {
      debugf("ICMP error does not include enough of the original packet", ntohs(iphdr.ip_len));
      return(0);
    }
    memcpy(responseToIpHdr,
	   &receivedPacket[HOPPING_IP4_HDRLEN+HOPPING_ICMP4_HDRLEN],
	   HOPPING_IP4_HDRLEN);
    memcpy(responseToIcmpHdr,
	   &receivedPacket[HOPPING_IP4_HDRLEN+HOPPING_ICMP4_HDRLEN+HOPPING_IP4_HDRLEN],
	   HOPPING_ICMP4_HDRLEN);
    *responseId = responseToIcmpHdr->icmp_id;
    debugf("using inner id %u in ICMP error", *responseId);
    if (responseToIpHdr->ip_p != IPPROTO_ICMP &&
	responseToIcmpHdr->icmp_type != HOPPING_ICMP_ECHO) {
      debugf("ICMP error includes some other packet than ICMP ECHO proto = %u icmp code = %u",
	     responseToIpHdr->ip_p,
	     responseToIcmpHdr->icmp_type);
      return(0);
    }
    *responseType = hopping_responseType_destinationUnreachable;
    debugf("DESTINATION UNREACHABLE from %s", hopping_addrtostring(&iphdr.ip_src));
    break;
    
  default:
    return(0);
    
  }
  
  //
  // Seems OK
  //
  
  return(1);
}

//
// Check that the packet is for this node and tht it is an
// ICMP packet
//

static int
hopping_packetisforus(char* receivedPacket,
		      int receivedPacketLength,
		      enum hopping_responseType receivedResponseType,
		      struct sockaddr_in* sourceAddress,
		      struct sockaddr_in* destinationAddress,
		      struct ip* responseToIpHdr,
		      struct icmp* responseToIcmpHdr) {
  
  struct ip iphdr;

  //
  // Some internal checks first
  //

  hopping_assert(receivedPacket != 0);
  hopping_assert(sourceAddress != 0);
  hopping_assert(destinationAddress != 0);
  
  //
  // Check the destination is our source address
  //
  
  memcpy(&iphdr,receivedPacket,HOPPING_IP4_HDRLEN);
  if (memcmp(&iphdr.ip_dst,&sourceAddress->sin_addr,sizeof(iphdr.ip_dst)) != 0) return(0);
  
  //
  // For ICMP error messages, we've already checked that the included
  // packet was an ICMP ECHO.  Now we need to additionally verify that
  // it was one sent from us to the destination.
  //
  
  if (receivedResponseType == hopping_responseType_destinationUnreachable ||
      receivedResponseType == hopping_responseType_timeExceeded) {
    
    debugf("checking that inner packet in the ICMP error was sent by us");
    debugf("  inner ip proto = %u", responseToIpHdr->ip_p);
    debugf("  inner ip len = %u", ntohs(responseToIpHdr->ip_len));
    debugf("  inner ip id = %u", responseToIpHdr->ip_id);
    debugf("  inner ip offset = %u", responseToIpHdr->ip_off);
    debugf("  inner icmp type = %u", responseToIcmpHdr->icmp_type);
    debugf("  inner icmp code = %u", responseToIcmpHdr->icmp_code);
    if (memcmp(&responseToIpHdr->ip_src,&sourceAddress->sin_addr,sizeof(responseToIpHdr->ip_src)) != 0) return(0);
    debugf("checking that inner packet in the ICMP error was sent to the destination we are testing");
    if (memcmp(&responseToIpHdr->ip_dst,&destinationAddress->sin_addr,sizeof(responseToIpHdr->ip_dst)) != 0) return(0);
    debugf("inner packet checks ok");
    
  }
  
  //
  // Looks like it is for us
  //
  
  return(1);
}

//
// Reporting progress: sent
//

static void
hopping_reportprogress_sent(hopping_idtype id,
			    unsigned char ttl,
			    int rexmit) {

  hopping_assert(rexmit == 0 || rexmit == 1);
  
  if (progress) {
    //if (lastprogressreportwassentpacket) {
    if (seenprogressreport) {
      printf("\n");
    }
    //}
    printf("%s #%u (TTL %u)...",
	   (rexmit ? "REXMIT" : "ECHO  "),
	   id,
	   ttl);
    lastprogressreportwassentpacket = 1;
    seenprogressreport = 1;
  }
}

//
// Reporting progress: received
//

static void
hopping_reportprogress_received(enum hopping_responseType responseType,
				hopping_idtype id,
				unsigned char ttl) {
  
  if (progress) {
    
    switch (responseType) {
      
    case hopping_responseType_echoResponse:
      printf(" <--- #%u REPLY", id);
      if (progressDetailed) {
	hopping_reportBriefConclusion();
      }
      break;
      
    case hopping_responseType_destinationUnreachable:
      printf(" <--- #%u UNREACH", id);
      if (progressDetailed) {
	hopping_reportBriefConclusion();
      }
      break;
      
    case hopping_responseType_timeExceeded:
      printf(" <--- #%u TTL EXPIRED", id);
      if (progressDetailed) {
	hopping_reportBriefConclusion();
      }
      break;
      
    case hopping_responseType_noResponse:
      printf(" <--- #%u NO RESPONSE", id);
      if (progressDetailed) {
	hopping_reportBriefConclusion();
      }
      break;
      
    case hopping_responseType_stillWaiting:
      fatalf("should not have this response type here");
      
    default:
      fatalf("invalid response type");
      
    }
    
    lastprogressreportwassentpacket = 0;
    seenprogressreport = 1;
  }
  
}

//
// Reporting progress: received other
//

static void
hopping_reportprogress_received_other() {
  
  if (progress) {
    printf(" <--- OTHER");
    lastprogressreportwassentpacket = 0;
    seenprogressreport = 1;
  }
  
}

//
// Reporting progress: received nothing
//

static void
hopping_reportprogress_noresponse(hopping_idtype id,
				  unsigned char ttl) {
  
  hopping_reportprogress_received(hopping_responseType_noResponse,
				  id,
				  ttl);
}

//
// Reporting progress: done
//

static void
hopping_reportprogress_end() {
  
  if (progress) {
    if (seenprogressreport) {
      printf("\n");
    }
  }
  
}

//
// Search for what probes in a given TTL range
// have not been sent yet
//

static unsigned int
hopping_probesnotyetsentinrange(unsigned char minTtlValue,
				unsigned char maxTtlValue) {

  int ttlsUsed[256];
  unsigned int count = 0;
  unsigned int id;
  unsigned int ttl;

  hopping_assert(minTtlValue <= maxTtlValue);
  memset(ttlsUsed,0,sizeof(ttlsUsed));
  
  for (id = 0; id < HOPPING_MAX_PROBES; id++) {
    struct hopping_probe* probe = &probes[id];
    if (probe->used) {
      ttlsUsed[probe->hops] = 1;
    }
  }
  
  for (ttl = (unsigned int)minTtlValue;
       ttl <= (unsigned int)maxTtlValue;
       ttl++) {
    if (!ttlsUsed[ttl]) count++;
  }

  debugf("hopping_probesnotyetsentinrange %u..%u: %u", minTtlValue, maxTtlValue, count);
  return(count);
}

//
// Can and should we continue the probing?
//

static int
hopping_shouldcontinue() {
  if (interrupt) return(0);
  if (probesSent >= maxProbes) return(0);
  if (hopsMinInclusive == hopsMaxInclusive) return(0);
  if (!hopping_probesnotyetsentinrange(hopsMinInclusive,hopsMaxInclusive)) return(0);
  return(1);
}

//
// Retransmit a given probe (by creating a new probe)
//

static void
hopping_retransmitactiveprobe(int sd,
			      struct sockaddr_in* destinationAddress,
			      struct sockaddr_in* sourceAddress,
			      struct hopping_probe* probe) {

  unsigned int expectedLen = HOPPING_IP4_HDRLEN + HOPPING_ICMP4_HDRLEN + icmpDataLength;
  hopping_idtype id = hopping_getnewid(probe->hops);
  struct hopping_probe* newProbe;

  hopping_assert(destinationAddress != 0);
  hopping_assert(sourceAddress != 0);
  hopping_assert(probe != 0);
  
  debugf("retransmitting probe id %u ttl %u", probe->id, probe->hops);
  
  newProbe = hopping_newprobe(id,probe->hops,expectedLen,probe);
  if (probe == 0) {
    fatalf("cannot allocate a new probe entry");
  }

  //
  // Send it
  //
  
  hopping_sendprobe(sd,
		    destinationAddress,
		    sourceAddress,
		    expectedLen,
		    newProbe);
  
  //
  // Report progress on screen
  //
  
  hopping_reportprogress_sent(id,newProbe->hops,1);
}

//
// Mark a probe and its predecessors as timed out
//

static void
hopping_markprobe_astimedout(struct hopping_probe* probe) {
  hopping_assert(probe != 0);
  hopping_assert(probe->responseType == hopping_responseType_stillWaiting);
  probe->responseType = hopping_responseType_noResponse;
  if (probe->previousTransmission != 0) {
    hopping_markprobe_astimedout(probe->previousTransmission);
  }
}

//
// Check to see if we need to retransmit any of the currently
// active (not responded to) probes
//

static void
hopping_retransmitactiveprobes(int sd,
			       struct sockaddr_in* destinationAddress,
			       struct sockaddr_in* sourceAddress) {

  struct timeval now;
  hopping_idtype otherid;
  
  hopping_assert(destinationAddress != 0);
  hopping_assert(sourceAddress != 0);
  
  //
  // Get current time
  //
  
  hopping_getcurrenttime(&now);
  
  //
  // If there are probes whose response has not arrived and their
  // timeouts expire, send retransmissions
  //
  
  for (otherid = 0; otherid < HOPPING_MAX_PROBES; otherid++) {
    
    struct hopping_probe* probe = &probes[otherid];
    if (probe->used && !probe->responded && probe->nextRetransmission == 0) {
      
      //
      // This probe has not seen an answer yet, nor is there an ongoing
      // retranmission for it yet. Check to see if it is time to send
      // a retransmission.
      //
      
      if (hopping_timeisless(&probe->initialTimeout,&now)) {
	
	//
	// Yes. Timeout has passed. But have we sent too many retries
	// already?
	//

	unsigned int triesSoFar = hopping_retries(probe);
	debugf("Considering new retransmission of probe TTL %u, triesSoFar = %u, maxTries = %u",
	       probe->hops,
	       triesSoFar,
	       maxTries);
	
	if (triesSoFar >= maxTries) {

	  //
	  // Bailing out, have attempted to send too many
	  // packets with this TTL already.
	  //

	  hopping_markprobe_astimedout(probe);
	  hopping_reportprogress_noresponse(probe->id,probe->hops);
	  
	} else {

	  //
	  // Ok. Request a retranmission to be sent...
	  //
	  
	  hopping_retransmitactiveprobe(sd,
					destinationAddress,
					sourceAddress,
					probe);
	  
	}
      }
      
    }
    
  }
  
}

//
// Construct and send a packet for a newly allocated probe
//

static void
hopping_sendprobe(int sd,
		  struct sockaddr_in* destinationAddress,
		  struct sockaddr_in* sourceAddress,
		  unsigned int expectedLen,
		  struct hopping_probe* probe) {
  
    unsigned int packetLength;
    char* packet;
    
    hopping_assert(destinationAddress != 0);
    hopping_assert(sourceAddress != 0);
    hopping_assert(probe != 0);
    
    //
    // Create a packet
    //
    
    hopping_constructicmp4packet(sourceAddress,
				 destinationAddress,
				 probe->id,
				 probe->hops,
				 icmpDataLength,
				 &packet,
				 &packetLength);
    if (expectedLen != packetLength) {
      fatalf("expected and resulting packet lengths do not agree (%u vs. %u)",
	     expectedLen, packetLength);
    }
    
    //
    // Send the packet
    //
    
    hopping_sendpacket(sd,
		       packet,
		       packetLength,
		       (struct sockaddr *)destinationAddress,
		       sizeof (struct sockaddr));
}

//
// Get a likely number of hops value for binary search
// start value, instead of blindly selecting 128 as the
// middle of the theoretical field. The 128 value is
// unlikely to be a real max TTL value in most cases.
//

static unsigned char
hopping_bestinitialguess(unsigned char from,
			 unsigned char to) {
  unsigned char selected = HOPPING_TYPICAL_INTERNET_HOP_COUNT + 1;
  if (selected < from) selected = from;
  if (selected > to) selected = to;
  return(selected);
}
  
//
// Get a likely number of hops value for binary search
// start value, for probes that are not the first probe
// but when we have not yet received any responses, so
// there is no knowledge of the search space reducing at
// all yet.
//

static unsigned char
hopping_bestinitialotherguess(unsigned char from,
			      unsigned char to,
			      hopping_ttl_test_function suitableTestFunction,
			      unsigned int numberOfTests) {
  return(hopping_bestbinarysearchvalue(HOPPING_TYPICAL_INTERNET_HOP_COUNT + 1,
				       HOPPING_TYPICAL_INTERNET_MAX_HOP_COUNT,
				       suitableTestFunction,
				       numberOfTests));
}
  
//
// Get a new search value in the possible range of values,
// based on binary (or tertiary or ...) search algorithm.
//

static unsigned char
hopping_bestbinarysearchvalue(unsigned char from,
			      unsigned char to,
			      hopping_ttl_test_function suitableTestFunction,
			      unsigned int numberOfTests) {
  
  unsigned char available[256];
  unsigned int nAvailable = 0;
  unsigned int i;
  unsigned char candidateIndex;
  unsigned char candidate;

  //
  // Sanity tests
  //

  debugf("hopping_bestbinarysearchvalue start %u..%u", from, to);
  hopping_assert(from <= to);
  hopping_assert(suitableTestFunction != 0);
  hopping_assert(numberOfTests > 0);
  
  //
  // First, collect the items in the range from..to that satisfy
  // the test function
  //
  
  for (i = (unsigned int)from; i <= (unsigned int)to; i++) {
    unsigned char ttl = (unsigned char)i;
    if ((*suitableTestFunction)(ttl)) {
      hopping_assert(nAvailable <= 255);
      available[nAvailable++] = ttl;
      debugf("TTL %u available, increasing navailable to %u", ttl, nAvailable);
    }
  }
  debugf("navailable finally %u", nAvailable);
  
  //
  // Then, figure out what items in the list deserve to be
  // picked, based on how many tests we have available.
  // For instance, with one test available we would halve
  // the search space, with two we divide it to three,
  // with three divide to four, etc.
  //

  candidateIndex = nAvailable / (numberOfTests+1);
  debugf("hopping_bestbinarysearchvalue candidate %u navailable %u numberoftests %u",
	 candidateIndex,
	 nAvailable,
	 numberOfTests);
  hopping_assert(candidateIndex < nAvailable);
  candidate = available[candidateIndex];
  debugf("binary search picks candidate %u from a pool of %u available candidates (number of tests = %u)",
	 candidate, nAvailable, numberOfTests);
  
  //
  // Done. Return the candidate
  //
  
  return(candidate);
}

//
// Re-initialize currentTtl to the currently learned range
//

static unsigned char
hopping_readjusttolearnedrange(int fromthetop) {

  if (readjust) {
    unsigned char newValue = fromthetop ? hopsMaxInclusive : hopsMinInclusive;
    debugf("readjusted currentTtl to %u (in range %u..%u)",
	   newValue, hopsMinInclusive, hopsMaxInclusive);
    return(newValue);
  } else {
    return(currentTtl);
  }

}

//
// Send as many probes as we are allowed to send
//

static void
hopping_sendprobes(int sd,
		   struct sockaddr_in* destinationAddress,
		   struct sockaddr_in* sourceAddress) {

  //
  // If there's room in the "bucket", send more new probes
  //
  
  while (bucket > 0 && hopping_shouldcontinue()) {
    
    struct hopping_probe* probe;
    unsigned int expectedLen;
    hopping_idtype id;
    
    //
    // Depending on algorithm, adjust behaviour
    //
    
    switch (algorithm) {

    case hopping_algorithms_random:
      
      debugf("before random selection, min = %u and max = %u",
	     hopsMinInclusive, hopsMaxInclusive);
      
      do {

	//
	// Random pick
	//
	
	currentTtl = (unsigned char)(((unsigned int)hopsMinInclusive +
				      (rand() % (((unsigned int)hopsMaxInclusive) - ((unsigned int)hopsMinInclusive) + 1))));
	
	//
	// If we've already sent probes on all TTLs in the current possible range of
	// TTLs, then just pick this random number and go with it!
	//
	
	if (hopping_countprobes_notsentinrange(hopsMinInclusive,hopsMaxInclusive)) break;
	
	//
	// If we've already sent a probe with this TTL earlier, pick another
	//
	
	if (hopping_thereisprobe_ttl(currentTtl)) continue;
	
      } while (1);
      
      debugf("selected a random ttl %u in range %u..%u", currentTtl, hopsMinInclusive, hopsMaxInclusive);
      break;

    case hopping_algorithms_sequential:
      
      //
      // Increase by one (unless this is the first probe
      //
      
      if (probesSent > 0 && currentTtl < 255) currentTtl++;

      //
      // If value falls outside currently learned range, readjust
      //
      
      if (currentTtl < hopsMinInclusive ||
	  currentTtl > hopsMaxInclusive) {

	currentTtl = hopping_readjusttolearnedrange(0);
	
      }
      
      //
      // Done
      //
      
      debugf("selected one larger ttl %u", currentTtl);
      break;
      
    case hopping_algorithms_reversesequential:
      
      //
      // Decrease by one (unless this is the first probe
      //
      
      if (probesSent > 0 && currentTtl > 0) currentTtl--;
      
      //
      // If value falls outside currently learned range, readjust
      //
      
      if (currentTtl < hopsMinInclusive ||
	  currentTtl > hopsMaxInclusive) {
	
	currentTtl = hopping_readjusttolearnedrange(1);
	
      }

      //
      // Done
      //
      
      debugf("selected one smaller ttl %u", currentTtl);
      break;
      
    case hopping_algorithms_binarysearch:
      
      if (likelyCandidates && probesSent == 0) {
	
	currentTtl = hopping_bestinitialguess(hopsMinInclusive,hopsMaxInclusive);
	
      } else if (likelyCandidates &&
		 hopping_responses() == 0 &&
		 probesSent < HOPPING_N_TYPICAL_HOP_COUNT_TRIES) {
	
	currentTtl = hopping_bestinitialotherguess(hopsMinInclusive,
						   hopsMaxInclusive,
						   hopping_thereisnoprobe_ttl,
						   bucket);
	
      } else {
	
	currentTtl = hopping_bestbinarysearchvalue(hopsMinInclusive,
						   hopsMaxInclusive,
						   hopping_thereisnoprobe_ttl,
						   bucket);
	
      }
      break;
      
    default:
      fatalf("invalid internal algorithm identifier");
      
    }

    //
    // Create a packet and send it
    //

    id = hopping_getnewid(currentTtl);
    expectedLen = HOPPING_IP4_HDRLEN + HOPPING_ICMP4_HDRLEN + icmpDataLength;
    probe = hopping_newprobe(id,currentTtl,expectedLen,0);
    if (probe == 0) {
      fatalf("cannot allocate a new probe entry");
    }
    hopping_sendprobe(sd,
		      destinationAddress,
		      sourceAddress,
		      expectedLen,
		      probe);

    //
    // Report progress on screen
    //
    
    hopping_reportprogress_sent(id,probe->hops,0);
        
  }

  //
  // If there are probes whose response has not arrived and their
  // timeouts expire, send retransmissions
  //
  
  hopping_retransmitactiveprobes(sd,
				 destinationAddress,
				 sourceAddress);
  
}

//
// The test main loop
//

static void
hopping_probingprocess(int sd,
		       int rd,
		       struct sockaddr_in* destinationAddress,
		       struct sockaddr_in* sourceAddress,
		       unsigned int startTtl) {
  
  enum hopping_responseType responseType;
  struct hopping_probe* responseToProbe;
  hopping_idtype responseId;
  unsigned char responseTtl;
  int receivedPacketLength;
  char* receivedPacket;

  //
  // Initialize task counters
  //

  bucket = parallel;
  
  //
  // Adjust TTL if needed
  //
  
  debugf("startTtl %u, maxTtl %u", startTtl, maxTtl);
  if (startTtl > maxTtl) {
    startTtl = maxTtl;
    debugf("reset startTtl to %u", startTtl);
  }
  
  if (algorithm == hopping_algorithms_reversesequential &&
      startTtl < maxTtl) {
    
    startTtl = maxTtl;
    debugf("reset startTtl to %u", startTtl);
    
  }
  
  currentTtl = startTtl;
  
  //
  // Loop
  //

  while (hopping_shouldcontinue()) {

    struct ip responseToIpHdr;
    struct icmp responseToIcmpHdr;
    int firstReception = 1;
    
    //
    // Send as many probes as we can
    //
    
    hopping_sendprobes(sd,
		       destinationAddress,
		       sourceAddress);
    
    //
    // Get as many responses as you can. On the first
    // call to hopping_receivepacket, we will wait if there's
    // no packet. On the second and subsequent calls we don't
    // wait, until we've again sent some probes.
    //
    
    while ((receivedPacketLength = hopping_receivepacket(rd,
							 &receivedPacket,
							 firstReception)) > 0) {
      
      debugf("received a packet of %u bytes", receivedPacketLength);
      
      //
      // Verify response packet (that it is for us, long enough, etc.)
      //
      
      if (!hopping_validatepacket(receivedPacket,
				  receivedPacketLength,
				  &responseType,
				  &responseId,
				  &responseTtl,
				  &responseToIpHdr,
				  &responseToIcmpHdr)) {
	
	debugf("invalid packet, ignoring");
	hopping_reportprogress_received_other();
	
      } else if (!hopping_packetisforus(receivedPacket,
					receivedPacketLength,
					responseType,
					sourceAddress,
					destinationAddress,
					&responseToIpHdr,
					&responseToIcmpHdr)) {
	
	debugf("packet not for us, ignoring");
	hopping_reportprogress_received_other();
	
      } else {
	
	debugf("packet was for us, taking into account");
	
	//
	// Register the response into our own database
	//
	
	hopping_registerResponse(responseType,
				 responseId,
				 responseTtl,
				 receivedPacketLength,
				 &responseToProbe);
	hopping_reportprogress_received(responseType,
					responseId,
					responseToProbe != 0 ? 0 : responseToProbe->hops);
	
      }

      //
      // Loop through any additional packets we might have received;
      // don't however wait for them.
      //
      
      firstReception = 0;
      
    }

    //
    // We did not get a packet, but got a timeout instead
    //
    
  }
  
  hopping_reportprogress_end();
  
}

//
// The main program for starting a test
//

static void
hopping_runtest(unsigned int startTtl,
		const char* interface,
		const char* destination) {

  struct sockaddr_in sourceAddress;
  struct sockaddr_in bindAddress;
  struct ifreq ifr;
  int hdrison = 1;
  int ifindex;
  int sd;
  int rd;
  
  //
  // Find out ifindex, own address, destination address
  //
  
  hopping_getifindex(interface,&ifindex,&ifr,&sourceAddress);
  hopping_getdestinationaddress(destination,&testDestinationAddress);
  
  //
  // Debugs
  //
  
  debugf("ifindex = %d", ifindex);
  debugf("source = %s", hopping_iptostring(&sourceAddress));
  debugf("destination = %s", hopping_iptostring(&testDestinationAddress));
  
  //
  // Get an output raw socket
  //
  
  if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    fatalp("socket() failed to get socket descriptor for using ioctl()");
  }
  
  if (setsockopt (sd, IPPROTO_IP, IP_HDRINCL, &hdrison, sizeof (hdrison)) < 0) {
    fatalp("setsockopt() failed to set IP_HDRINCL");
  }
  
  if (setsockopt (sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof (ifr)) < 0) {
    fatalp("setsockopt() failed to bind to interface");
  }

  //
  // Get an input raw socket
  //
  
  if ((rd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
    fatalp("cannot create input raw socket");
  }
  
  bindAddress.sin_family = AF_INET;
  bindAddress.sin_port = 0;
  bindAddress.sin_addr.s_addr = sourceAddress.sin_addr.s_addr;
  
  if (bind(rd, (struct sockaddr*) &bindAddress, sizeof(bindAddress)) == -1) {
    fatalp("cannot bind input raw socket");
  }

  //
  // Start the main loop
  //
  
  hopping_probingprocess(sd,rd,&testDestinationAddress,&sourceAddress,startTtl);
  
  //
  // Done. Return.
  //
  
}

//
// See if there were any responses of any kind yet
//

static unsigned int
hopping_responses() {

  unsigned int count = 0;
  unsigned int id;
  
  for (id = 0; id < HOPPING_MAX_PROBES; id++) {
    struct hopping_probe* probe = &probes[id];
    if (probe->used &&
	probe->responded) {
      count++;
    }
  }
  
  return(count);
}

//
// See if there were any unreachable errors
//

static unsigned int
hopping_replyresponses() {

  unsigned int count = 0;
  unsigned int id;
  
  for (id = 0; id < HOPPING_MAX_PROBES; id++) {
    struct hopping_probe* probe = &probes[id];
    if (probe->used &&
	probe->responded &&
	probe->responseType == hopping_responseType_echoResponse) {
      count++;
    }
  }
  
  return(count);
}

//
// See if there were any time exceeded errors
//

static unsigned int
hopping_timeexceededresponses() {

  unsigned int count = 0;
  unsigned int id;
  
  for (id = 0; id < HOPPING_MAX_PROBES; id++) {
    struct hopping_probe* probe = &probes[id];
    if (probe->used &&
	probe->responded &&
	probe->responseType == hopping_responseType_timeExceeded) {
      count++;
    }
  }
  
  return(count);
}

//
// See if there were any unreachable errors
//

static unsigned int
hopping_unreachableresponses() {

  unsigned int count = 0;
  unsigned int id;
  
  for (id = 0; id < HOPPING_MAX_PROBES; id++) {
    struct hopping_probe* probe = &probes[id];
    if (probe->used &&
	probe->responded &&
	probe->responseType == hopping_responseType_destinationUnreachable) {
      count++;
    }
  }
  
  return(count);
}

//
// Output the current state of (brief) conclusion (as much as we know)
// from the probing process
//

static void
hopping_reportBriefConclusion() {
  if (hopsMinInclusive == hopsMaxInclusive) {
    printf(" [%u hops away]", hopsMinInclusive);
  } else if (hopsMinInclusive <= 1 && hopsMaxInclusive >= maxTtl) {
    printf(" [unknown hops away]");
  } else {
    printf(" [%u.. %u hops away]",
	   hopsMinInclusive,
	   hopsMaxInclusive);
  }
}

//
// Output a conclusion (as much as we know) from the
// probing process
//

static void
hopping_reportConclusion() {
  
  unsigned int repl = hopping_replyresponses();
  unsigned int exc = hopping_timeexceededresponses();
  unsigned int unreach = hopping_unreachableresponses();
  const char* testDestinationAddressString = hopping_addrtostring(&testDestinationAddress.sin_addr);

  if (!machineReadable) {
    printf("%s (%s) is ", testDestination, testDestinationAddressString);
  }
  
  if (hopsMinInclusive == hopsMaxInclusive) {
    printf("%u", hopsMinInclusive);
  } else if (hopsMinInclusive <= 1 && hopsMaxInclusive >= maxTtl) {
    printf("unknown");
  } else {
    if (machineReadable) {
      printf("%u-%u",
	     hopsMinInclusive,
	     hopsMaxInclusive);
    } else {
      printf("between %u and %u",
	     hopsMinInclusive,
	     hopsMaxInclusive);
    }
  }
  
  if (machineReadable) {
    printf(":");
  } else {
    printf(" hops away");
  }
  
  if (repl == 0 && unreach > 0) {
    if (machineReadable)
      printf("unknown");
    else
      printf(", but may not be reachable");
  } else if (repl > 0 && unreach > 0) {
    if (machineReadable)
      printf("mixed");
    else
      printf(" and reachable, but also gives reachability errors");
  } else if (repl > 0 && unreach == 0) {
    if (machineReadable)
      printf("reachable");
    else
      printf(" and reachable");
  } else if (exc > 0) {
    if (machineReadable)
      printf("unknown");
    else
      printf(", not sure if it is reachable");
  } else {
    if (machineReadable)
      printf("unknown");
    else
      printf(", not sure if it is reachable as we got no ICMPs back at all");
  }
  
  printf("\n");
  
}

//
// Count the number of probes sent
//

static unsigned int
hopping_count_probes_sent() {

  unsigned int count = 0;
  hopping_idtype id;
  
  for (id = 0; id < HOPPING_MAX_PROBES; id++) {
    struct hopping_probe* probe = &probes[id];
    if (probe->used) {
      count++;
    }
  }

  return(count);
}
  
//
// Print out brief statistics related the process of probing
//

static void
hopping_reportStatsBrief() {
  if (machineReadable) {
      printf("%u\n", hopping_count_probes_sent());
  } else  {
      printf("%u probes sent\n", hopping_count_probes_sent());
  }
}

//
// Print out full statistics related the process of probing
//

static void
hopping_reportStatsFull() {
  
  unsigned int nProbes = hopping_count_probes_sent();
  unsigned int nRetransmissions = 0;
  unsigned int nResponses = 0;
  unsigned int nEchoReplies = 0;
  unsigned int nDestinationUnreachables = 0;
  unsigned int nTimeExceededs = 0;
  unsigned int nNoResponses = 0;
  unsigned int nNoResponseTimeouts = 0;
  unsigned int nDuplicateResponses = 0;
  unsigned int probeBytes = 0;
  unsigned int responseBytes = 0;
  unsigned int hopsused[256];
  unsigned int id;
  unsigned long shortestDelay = 0xffffffff;
  unsigned long longestDelay = 0;
  unsigned int ttl;
  int seenttl;
  
  memset(hopsused,0,sizeof(hopsused));
  for (id = 0; id < HOPPING_MAX_PROBES; id++) {
    struct hopping_probe* probe = &probes[id];
    if (probe->used) {

      //
      // Basic statistics: number of probes, bytes, etc.
      //
      
      hopsused[probe->hops]++;
      probeBytes += probe->probeLength;

      //
      // Count retransmissions
      //
      
      if (probe->previousTransmission != 0) {
	nRetransmissions++;
      }

      //
      // Look at the possible responses
      //
      
      if (probe->responded) {
	
	//
	// Basic response statistics
	//
	
	nResponses++;
	responseBytes += probe->responseLength;
	nDuplicateResponses += probe->duplicateResponses;
	
	//
	// Calculate response timings
	//
	
	if (probe->delayUSecs < shortestDelay) shortestDelay = probe->delayUSecs; 
	if (probe->delayUSecs > longestDelay) longestDelay = probe->delayUSecs;

	//
	// Look at the response types
	//
	
	switch (probe->responseType) {
	case hopping_responseType_echoResponse:
	  nEchoReplies++;
	  break;
	case hopping_responseType_destinationUnreachable:
	  nDestinationUnreachables++;
	  break;
	case hopping_responseType_timeExceeded:
	  nTimeExceededs++;
	  break;
	case hopping_responseType_stillWaiting:
	case hopping_responseType_noResponse:
	  fatalf("should not have this response type");
	default:
	  fatalf("invalid response type");
	}
	
      } else {

	nNoResponses++;
	if (probe->responseType == hopping_responseType_noResponse) {
	  
	  nNoResponseTimeouts++;
	  
	}
	
      }
    }
  }
  
  printf("\n");
  printf("Statistics:\n");
  printf("\n");
  printf("%12s    algorithm\n", hopping_algorithm2name(algorithm));
  printf("  %10u    allowed parallel probes\n", parallel);
  printf("  %10s    readjust search space based on responses\n", readjust ? "yes" : "no");
  printf("  %10u    probes sent out\n", nProbes);
  if (nProbes > 0) {
    printf("                on TTLs: ");
    seenttl = 0;
    for (ttl = 0; ttl < 256; ttl++) {
      if (hopsused[ttl]) {
	if (seenttl) printf(", ");
	printf("%u", ttl);
	if (hopsused[ttl] > 1) {
	  printf(" (%u times)", hopsused[ttl]);
	}
	seenttl = 1;
      }
    }
    printf("\n");
  }
  printf("  %10u    probes were retransmissions\n", nRetransmissions);
  printf("%12u    bytes used in the probes\n", probeBytes);
  printf("  %10u    responses received\n", nResponses);
  printf("%12u    bytes used in the responses\n", responseBytes);
  printf("  %10u    echo replies received\n", nEchoReplies);
  printf("  %10u    destination unreachable errors received\n", nDestinationUnreachables);
  printf("  %10u    time exceeded errors received\n", nTimeExceededs);
  if (nResponses > 0) {
    printf("%12.4f    shortest response delay (ms)\n", ((float)shortestDelay / 1000.0));
    printf("%12.4f    longest response delay (ms)\n", ((float)longestDelay / 1000.0));
  }
  printf("  %10u    additional duplicate responses\n", nDuplicateResponses);
  printf("  %10u    probes without responses\n", nNoResponses);
  printf("  %10u    timeouts waiting for probes with a given TTL\n", nNoResponseTimeouts);
}

//
// Print out statistics related the process of probing
//

static void
hopping_reportStats() {
  if (fullStatistics) hopping_reportStatsFull();
  else if (briefStatistics) hopping_reportStatsBrief();
}

//
// Interrupts (Ctrl-C) during program execution
// should cause the current probing process to end
// and results printed out.
//

static void
hopping_interrupt(int dummy) {
  interrupt = 1;
}

//
// The main program -----------------------------------------------------------------------
//

int
main(int argc,
     char** argv) {

  //
  // Initialize
  //
  
  srand(time(0));
  
  //
  // Process arguments
  //
  
  argc--; argv++;
  while (argc > 0) {
    
    if (strcmp(argv[0],"-version") == 0) {
      
      printf("version 0.2\n");
      exit(0);
      
    } else if (strcmp(argv[0],"-debug") == 0) {
      
      debug = 1;
      
    } else if (strcmp(argv[0],"-no-debug") == 0) {
      
      debug = 0;
      
    } else if (strcmp(argv[0],"-progress") == 0) {
      
      progress = 1;
      
    } else if (strcmp(argv[0],"-quiet") == 0 ||
	       strcmp(argv[0],"-no-progress") == 0) {
      
      progress = 0;
      progressDetailed = 0;
      
    } else if (strcmp(argv[0],"-detailed-progress") == 0) {
      
      progress = 1;
      progressDetailed = 1;

    } else if (strcmp(argv[0],"-no-detailed-progress") == 0) {
      
      progressDetailed = 0;

    } else if (strcmp(argv[0],"-machine-readable") == 0) {
      
      machineReadable = 1;

    } else if (strcmp(argv[0],"-human-readable") == 0) {
      
      machineReadable = 0;

    } else if (strcmp(argv[0],"-statistics") == 0) {

      briefStatistics = 1;
      fullStatistics = 0;

    } else if (strcmp(argv[0],"-full-statistics") == 0) {

      briefStatistics = 0;
      fullStatistics = 1;

    } else if (strcmp(argv[0],"-no-statistics") == 0) {

      briefStatistics = 0;
      fullStatistics = 0;
      
    } else if (strcmp(argv[0],"-size") == 0 && argc > 1 && isdigit(argv[1][0])) {

      icmpDataLength = atoi(argv[1]);
      argc--; argv++;

    } else if (strcmp(argv[0],"-maxttl") == 0 && argc > 1 && isdigit(argv[1][0])) {

      maxTtl = atoi(argv[1]);
      debugf("maxTtl set to %u", maxTtl);
      if (maxTtl < 1)
	fatalf("Cannot set -maxttl to a value less than 1");
      argc--; argv++;

    } else if (strcmp(argv[0],"-maxprobes") == 0 && argc > 1 && isdigit(argv[1][0])) {

      maxProbes = atoi(argv[1]);
      debugf("maxProbes set to %u", maxProbes);
      if (maxProbes < 1)
	fatalf("Cannot set -maxprobes to a value less than 1");
      argc--; argv++;

    } else if (strcmp(argv[0],"-maxtries") == 0 && argc > 1 && isdigit(argv[1][0])) {
      
      maxTries = atoi(argv[1]);
      debugf("maxTries set to %u", maxTries);
      if (maxTries < 1)
	fatalf("Cannot set -maxtries to a value less than 1");
      argc--; argv++;
      
    } else if (strcmp(argv[0],"-parallel") == 0 && argc > 1 && isdigit(argv[1][0])) {

      parallel = atoi(argv[1]);
      if (parallel < 1 || parallel >= 100) {
	fatalf("invalid number of parallel probes");
      }
      debugf("parallel set to %u", parallel);
      argc--; argv++;

    } else if (strcmp(argv[0],"-no-parallel") == 0) {
      
      parallel = 1;
      
    } else if (strcmp(argv[0],"-algorithm") == 0 && argc > 1) {

      if (strcmp(argv[1],"random") == 0) {
	algorithm = hopping_algorithms_random;
      } else if (strcmp(argv[1],"sequential") == 0) {
	algorithm = hopping_algorithms_sequential;
      } else if (strcmp(argv[1],"reversesequential") == 0) {
	algorithm = hopping_algorithms_reversesequential;
      } else if (strcmp(argv[1],"binarysearch") == 0) {
	algorithm = hopping_algorithms_binarysearch;
      } else {
	fatalf("invalid algorithm value %s (expecting %s)",
	       argv[1], hopping_algorithms_string);
      }
      
      argc--; argv++;
      
    } else if (strcmp(argv[0],"-likely-candidates") == 0) {

      likelyCandidates = 1;
      
    } else if (strcmp(argv[0],"-no-likely-candidates") == 0) {

      likelyCandidates = 0;
      
    } else if (strcmp(argv[0],"-readjust") == 0) {

      readjust = 1;
      
    } else if (strcmp(argv[0],"-no-readjust") == 0) {

      readjust = 0;
      
    } else if (strcmp(argv[0],"-interface") == 0 && argc > 1) {

      interface = argv[1];
      argc--; argv++;
      
    } else if (strcmp(argv[0],"-startttl") == 0 && argc > 1 && isdigit(argv[1][0])) {
      
      startTtl = atoi(argv[1]);
      if (startTtl > 255) {
	fatalf("invalid TTL value");
      }
      argc--; argv++;
      
    } else if (argv[0][0] == '-') {
      
      fatalf("unrecognised option %s", argv[0]);
      
    } else if (argc > 1) {
      
      fatalf("too many arguments");
      
    } else {
      
      testDestination = argv[0];
      
    }
    
    argc--; argv++;
    
  }
  
  signal(SIGINT, hopping_interrupt);
  
  hopping_runtest(startTtl,
		  interface,
		  testDestination);
  
  if (conclusion) {
    hopping_reportConclusion();
  }
  
  hopping_reportStats();
  
  exit(0);
}
