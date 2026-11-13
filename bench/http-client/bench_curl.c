// libcurl benchmark: bench_curl <url> <warm|cold|conc> <n> [workers] [h2]
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
static unsigned long long now_ns(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1000000000ull+t.tv_nsec;}
static size_t sink(char*p,size_t s,size_t n,void*u){(void)p;(void)u;return s*n;}
static int cmp(const void*a,const void*b){unsigned long long x=*(unsigned long long*)a,y=*(unsigned long long*)b;return x<y?-1:x>y;}
static const char*CA_DEF="/home/lement/projects/zig-runner-http-client/bench/http-client/certs/cert.pem";
static CURL*mk(const char*url,int fresh,int h2){CURL*e=curl_easy_init();
 curl_easy_setopt(e,CURLOPT_URL,url);curl_easy_setopt(e,CURLOPT_CAINFO,getenv("CA_FILE")?getenv("CA_FILE"):CA_DEF);curl_easy_setopt(e,CURLOPT_WRITEFUNCTION,sink);
 curl_easy_setopt(e,CURLOPT_HTTP_VERSION,h2?CURL_HTTP_VERSION_2TLS:CURL_HTTP_VERSION_1_1);
 if(fresh){curl_easy_setopt(e,CURLOPT_FRESH_CONNECT,1L);curl_easy_setopt(e,CURLOPT_FORBID_REUSE,1L);}
 return e;}
int main(int argc,char**argv){
 const char*url=argv[1],*mode=argv[2];int n=atoi(argv[3]);int w=argc>4?atoi(argv[4]):1;int h2=argc>5;
 curl_global_init(CURL_GLOBAL_DEFAULT);
 unsigned long long*lat=calloc(n,8);int fails=0;double ph[5]={0};
 unsigned long long t0=now_ns();
 if(strcmp(mode,"conc")){
  int cold=!strcmp(mode,"cold");CURL*e=mk(url,cold,h2);
  for(int i=0;i<n;i++){unsigned long long a=now_ns();CURLcode rc=curl_easy_perform(e);lat[i]=now_ns()-a;if(rc)fails++;
   double v;curl_easy_getinfo(e,CURLINFO_NAMELOOKUP_TIME,&v);ph[0]+=v;curl_easy_getinfo(e,CURLINFO_CONNECT_TIME,&v);ph[1]+=v;
   curl_easy_getinfo(e,CURLINFO_APPCONNECT_TIME,&v);ph[2]+=v;curl_easy_getinfo(e,CURLINFO_STARTTRANSFER_TIME,&v);ph[3]+=v;curl_easy_getinfo(e,CURLINFO_TOTAL_TIME,&v);ph[4]+=v;}
  curl_easy_cleanup(e);
 } else {
  CURLM*m=curl_multi_init();if(h2)curl_multi_setopt(m,CURLMOPT_PIPELINING,CURLPIPE_MULTIPLEX);
  unsigned long long*start=calloc(w,8);CURL**hs=calloc(w,sizeof(CURL*));int started=0,done=0,running=0;
  #define START(i) do{hs[i]=mk(url,0,h2);curl_easy_setopt(hs[i],CURLOPT_PRIVATE,(void*)(long)(i));start[i]=now_ns();curl_multi_add_handle(m,hs[i]);started++;running++;}while(0)
  for(int i=0;i<w&&started<n;i++)START(i);
  while(done<n){int nr;curl_multi_perform(m,&nr);int q;CURLMsg*msg;
   while((msg=curl_multi_info_read(m,&q))){if(msg->msg==CURLMSG_DONE){void*p;curl_easy_getinfo(msg->easy_handle,CURLINFO_PRIVATE,&p);int i=(int)(long)p;
     if(msg->data.result)fails++;lat[done++]=now_ns()-start[i];curl_multi_remove_handle(m,hs[i]);curl_easy_cleanup(hs[i]);running--;if(started<n)START(i);}}
   if(done<n)curl_multi_poll(m,NULL,0,50,NULL);}
 }
 unsigned long long wall=now_ns()-t0;qsort(lat,n,8,cmp);unsigned long long sum=0;for(int i=0;i<n;i++)sum+=lat[i];
 struct rusage ru;getrusage(RUSAGE_SELF,&ru);
 printf("curl%s %s n=%d p50=%llu p99=%llu mean=%llu wall_ms=%llu cpu_ms=%ld rss_kb=%ld fails=%d",h2?"-h2":"",mode,n,lat[n/2]/1000,lat[n*99/100]/1000,sum/n/1000,wall/1000000,
  (ru.ru_utime.tv_sec+ru.ru_stime.tv_sec)*1000+(ru.ru_utime.tv_usec+ru.ru_stime.tv_usec)/1000,ru.ru_maxrss,fails);
 if(!strcmp(mode,"cold"))printf(" phases_us[dns,tcp,tls,ttfb,total]=%.0f,%.0f,%.0f,%.0f,%.0f",ph[0]/n*1e6,ph[1]/n*1e6,ph[2]/n*1e6,ph[3]/n*1e6,ph[4]/n*1e6);
 printf("\n");return 0;}
