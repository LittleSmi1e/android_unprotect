/* 
 * drizzleDumper Code By Drizzle.Risk 
 * file: drizzleDumper.c 
 */  
  
#include "drizzleDumper.h"  
  
  
// 主函数main  
int main(int argc, char *argv[]) {  
  
  printf("[>>>]  This is drizzleDumper [<<<]\n");  
  printf("[>>>]    code by Drizzle     [<<<]\n");  
  printf("[>>>]        2016.05         [<<<]\n");  
    
  // 脱壳工具drizzleDumper在工作的实收需要3个参数（需要脱壳的apk的package_name、脱壳等待的时间wait_times(s)）  
  if(argc <= 1)   
  {  
    printf("[*]  Useage : ./drizzleDumper package_name wait_times(s)\n[*]  The wait_times(s) means how long between the two Scans, default 0s  \n[*]  if successed, you can find the dex file in /data/local/tmp\n[*]  Good Luck!\n");  
    return 0;  
  }  
  
  // 由于脱壳的原理是基于进程的ptrace，需要有root权限  
  if(getuid() != 0)   
  {  
    printf("[*]  Device Not root!\n");  
    return -1;  
  }  
  
  double wait_times = 0.01;  
  // 脱壳工具drizzleDumper在工作的实收需要3个参数（需要脱壳的apk的package_name、脱壳等待的时间wait_times(s)）  
  if(argc >= 3)  
  {  
    // 获取加固脱壳的等待时间  
    wait_times = strtod(argv[2], NULL);  
    printf("[*]  The wait_times is %ss\n", argv[2]);  
  }  
    
  // 获取需要被脱壳的加固apk的包名  
  char *package_name = argv[1];  
  printf("[*]  Try to Find %s\n", package_name);  
  
  uint32_t pid = -1;  
  
  int i = 0;  
  int mem_file;  
  uint32_t clone_pid;  
  char *extra_filter;  
  char *dumped_file_name;  
  
  // 进入循环  
  while(1)  
  {  
      // 休眠等待一段时间  
      sleep(wait_times);  
        
      pid = -1;  
      // 获取加固需要被脱壳的apk的进程pid  
      pid = get_process_pid(package_name);  
      // 判断获取的进程pid是否有效  
      if(pid < 1 || pid == -1)  
      {  
          continue;  
      }  
      printf("[*]  pid is %d\n", pid);  
  
      // 获取进程pid的一个线程tid，方便后面进行ptrace附加  
      clone_pid = get_clone_pid(pid);  
      if(clone_pid <= 0)   
      {  
        continue;  
      }  
      printf("[*]  clone pid is %d\n", clone_pid);  
  
      memory_region memory;  
      printf("[*]  ptrace [clone_pid] %d\n", clone_pid);  
        
      // 对指定pid进程的克隆即tid进程ptrace附加，获取指定pid进程的内存模块基址  
      mem_file = attach_get_memory(clone_pid);  
      // 对获取到的内存有效数据的进行校验3次即最多进行3次脱壳尝试  
      if(mem_file == -10201)   
      {  
        continue;  
      }  
      else if(mem_file == -20402)  
      {  
         //continue;  
      }  
      else if(mem_file == -30903)  
      {  
         //continue  
      }  
        
      /**** 
       *static const char* static_safe_location = "/data/local/tmp/"; 
       *static const char* suffix = "_dumped_"; 
       ****/  
      
      // 申请内存空间保存内存dump出来的dex文件的名称  
      dumped_file_name = malloc(strlen(static_safe_location) + strlen(package_name) + strlen(suffix));  
      // 格式化生成存dump出来的dex文件的名称  
      sprintf(dumped_file_name, "%s%s%s", static_safe_location, package_name, suffix);  
        
      printf("[*]  Scanning dex ...\n");  
        
      // 通过ptrace附件目标pid进程，在目标进程的pid中进行dex文件的搜索然后进行内存dump  
      if(find_magic_memory(clone_pid, mem_file, &memory, dumped_file_name) <= 0)  
      {  
        printf("[*]  The magic was Not Found!\n");  
        ptrace(PTRACE_DETACH, clone_pid, NULL, 0);  
        close(mem_file);  
        continue;  
      }  
      else  
      {  
         // dex的内存dump成功，跳出循环  
         close(mem_file);  
         ptrace(PTRACE_DETACH, clone_pid, NULL, 0);  
         break;  
      }  
   }  
  
  printf("[*]  Done.\n\n");  
  return 1;  
}  
  
// 获取指定进程的一个线程tid  
uint32_t get_clone_pid(uint32_t service_pid)  
{  
  DIR *service_pid_dir;  
  char service_pid_directory[1024];  
    
  // 格式化字符串  
  sprintf(service_pid_directory, "/proc/%d/task/", service_pid);  
  // 查询指定进程的pid的线程TID的信息  
  if((service_pid_dir = opendir(service_pid_directory)) == NULL)  
  {  
    return -1;  
  }  
  
  struct dirent* directory_entry = NULL;  
  struct dirent* last_entry = NULL;  
  
  // 获取指定pid进程的线程TID  
  while((directory_entry = readdir(service_pid_dir)) != NULL)  
  {  
    last_entry = directory_entry;  
  }  
  if(last_entry == NULL)  
    return -1;  
  
  closedir(service_pid_dir);  
  
  // 返回获取到的指定pid的线程tid  
  return atoi(last_entry->d_name);  
}  
  
  
// 通过运行的apk的名称的获取进程的pid  
uint32_t get_process_pid(const char *target_package_name)  
{  
  char self_pid[10];  
  sprintf(self_pid, "%u", getpid());  
  
  DIR *proc = NULL;  
  
  if((proc = opendir("/proc")) == NULL)  
    return -1;  
  
  struct dirent *directory_entry = NULL;  
  while((directory_entry = readdir(proc)) != NULL)  
  {  
  
    if (directory_entry == NULL)  
      return -1;  
  
    if (strcmp(directory_entry->d_name, "self") == 0 || strcmp(directory_entry->d_name, self_pid) == 0)  
        continue;  
  
      char cmdline[1024];  
      snprintf(cmdline, sizeof(cmdline), "/proc/%s/cmdline", directory_entry->d_name);  
      FILE *cmdline_file = NULL;  
      if((cmdline_file = fopen(cmdline, "r")) == NULL)  
          continue;  
  
      char process_name[1024];  
      fscanf(cmdline_file, "%s", process_name);  
      fclose(cmdline_file);  
  
      if(strcmp(process_name, target_package_name) == 0)  
      {  
         closedir(proc);  
         return atoi(directory_entry->d_name);  
      }  
    }  
  
    closedir(proc);  
    return -1;  
}  
  
//  在目标进程的内存空间中进行dex文件的搜索  
int find_magic_memory(uint32_t clone_pid, int memory_fd, memory_region *memory , const char *file_name) {  
      
  int ret = 0;  
  char maps[2048];  
    
  // 格式化字符串得到/proc/pid/maps  
  snprintf(maps, sizeof(maps), "/proc/%d/maps", clone_pid);  
  
  FILE *maps_file = NULL;  
  // 打开文件/proc/pid/maps，获取指定pid进程的内存分布信息  
  if((maps_file = fopen(maps, "r")) == NULL)  
  {  
    printf(" [+] fopen %s Error  \n" , maps);  
    return -1;  
  }  
  
   char mem_line[1024];  
   // 循环读取文件/proc/pid/maps中的pid进程的每一条内存分布信息  
   while(fscanf(maps_file, "%[^\n]\n", mem_line) >= 0)  
   {  
     char mem_address_start[10]={0};  
     char mem_address_end[10]={0};  
     char mem_info[1024]={0};  
  
     // 解析pid进程的的内存分布信息--内存分布起始地址、内存分布结束地址等  
     sscanf(mem_line, "%8[^-]-%8[^ ]%*s%*s%*s%*s%s", mem_address_start, mem_address_end, mem_info);  
     memset(mem_line , 0 ,1024);  
       
     // 获取内存分布起始地址的大小  
     uint32_t mem_start = strtoul(mem_address_start, NULL, 16);  
     memory->start = mem_start;  
     // 获取内存分布结束地址的大小  
     memory->end = strtoul(mem_address_end, NULL, 16);  
     // 获取实际的内存区间大小  
     int len =  memory->end - memory->start;  
     // 过滤掉不符合条件的内存分布区间  
     if(len <= 10000)  
     {//too small  
        continue;  
     }  
     else if(len >= 150000000)  
     {//too big  
         continue;  
     }  
  
      char each_filename[254] = {0};  
      char randstr[10] = {0};  
      sprintf(randstr ,"%d", rand()%9999);  
  
      // 拼接字符串得到dump的dex文件的生成名称  
      strncpy(each_filename , file_name , 200); //防溢出  
      strncat(each_filename , randstr , 10);  
      strncat(each_filename , ".dex" , 4);  
  
       // 先将pid进程内存文件句柄的指针置文件开头  
       lseek64(memory_fd , 0 , SEEK_SET);     
       // 设置pid进程内存文件句柄的指针为内存分布起始地址  
       off_t r1 = lseek64(memory_fd , memory->start , SEEK_SET);  
       if(r1 == -1)  
       {  
           //do nothing  
       }  
       else  
       {  
          // 根据内存分布区间的大小申请内存空间  
          char *buffer = malloc(len);  
          // 读取pid进程的指定区域的内存数据  
          ssize_t readlen = read(memory_fd, buffer, len);  
          printf("meminfo: %s ,len: %d ,readlen: %d, start: %x\n", mem_info, len, readlen, memory->start);  
            
          // 对读取的内存分布区域的数据进行dex文件的扫描和查找  
          if(buffer[1] == 'E' && buffer[2] == 'L' && buffer[3] == 'F')  
          {  
            free(buffer);  
  
            continue;  
          }  
            
          // 查找到dex文件所在的内存区域  
          if(buffer[0] == 'd' && buffer[1] == 'e' && buffer[2] == 'x' && buffer[3] == '\n'  && buffer[4] == '0' && buffer[5] == '3')  
          {  
            printf(" [+] find dex, len : %d , info : %s\n" , readlen , mem_info);  
  
            DexHeader header;  
            char real_lenstr[10]={0};  
  
            // 获取内存区域中dex文件的文件头信息  
            memcpy(&header , buffer ,sizeof(DexHeader));  
            sprintf(real_lenstr , "%x" , header.fileSize);  
  
            // 通过dex文件头信息，获取到整个dex文件的大小  
            long real_lennum = strtol(real_lenstr , NULL, 16);  
            printf(" [+] This dex's fileSize: %d\n", real_lennum);  
  
            // 对dex文件所在的内存区域进行内存dump  
            if(dump_memory(buffer , len , each_filename)  == 1)  
            {  
              // 打印dump的dex文件的名称  
              printf(" [+] dex dump into %s\n", each_filename);  
              free(buffer);  
              continue;  
            }  
            else  
            {  
             printf(" [+] dex dump error \n");  
            }  
  
            }  
              
            free(buffer);  
           }  
  
           // 前面的内存方法搜索没有查找dex文件的内存，尝试下面的内存+8位置进行搜索  
           // 具体什么原因没太明白??  
           lseek64(memory_fd , 0 , SEEK_SET);   //保险，先归零  
           r1 = lseek64(memory_fd , memory->start + 8 , SEEK_SET); //不用 pread，因为pread用的是lseek  
           if(r1 == -1)  
           {  
               continue;  
           }  
           else  
           {  
              char *buffer = malloc(len);  
              ssize_t readlen = read(memory_fd, buffer, len);  
  
              if(buffer[0] == 'd' && buffer[1] == 'e' && buffer[2] == 'x' && buffer[3] == '\n'  && buffer[4] == '0' && buffer[5] == '3')  
              {  
                printf(" [+] Find dex! memory len : %d \n" , readlen);  
  
                DexHeader header;  
                char real_lenstr[10]={0};  
  
                // 获取内存dex文件的文件头信息  
                memcpy(&header , buffer ,sizeof(DexHeader));  
                sprintf(real_lenstr , "%x" , header.fileSize);  
  
                // 通过dex文件头信息，获取到整个dex文件的大小  
                long real_lennum = strtol(real_lenstr , NULL, 16);  
                printf(" [+] This dex's fileSize: %d\n", real_lennum);  
  
                // 对dex文件所在的内存区域进行内存dump  
                if(dump_memory(buffer , len , each_filename)  == 1)  
                {  
                    printf(" [+] dex dump into %s\n", each_filename);  
                    free(buffer);  
                    continue;   //如果本次成功了，就不尝试其他方法了  
                }  
                else  
                {  
                 printf(" [+] dex dump error \n");  
                }  
              }  
                
              free(buffer);  
           }  
        }  
    fclose(maps_file);  
      
    return ret;  
}  
  
  
// 从内存中dump数据到文件中  
int dump_memory(const char *buffer , int len , char each_filename[])  
{  
    int ret = -1;  
      
    // 创建文件  
    FILE *dump = fopen(each_filename, "wb");  
    // 将需要dump的内存数据写入到/data/local/tmp文件路径下  
    if(fwrite(buffer, len, 1, dump) != 1)  
    {  
        ret = -1;  
    }  
    else  
    {  
        ret = 1;  
    }  
  
    fclose(dump);  
    return ret;  
}  
  
// 获取指定附加pid进程的内存模块基址  
int attach_get_memory(uint32_t pid) {  
      
  char mem[1024];  
  bzero(mem,1024);  
    
  // 格式化字符串得到字符串/proc/pid/mem  
  snprintf(mem, sizeof(mem), "/proc/%d/mem", pid);  
  
  int ret = -1;  
  int mem_file;  
    
  // 尝试ptrace附加目标pid进程  
  ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);  
  // 对ptrace附加目标pid进程的操作结果进行判断  
  if (0 != ret)  
  {  
      int err = errno;  //这时获取errno  
      if(err == 1) //EPERM  
      {  
          return -30903;    //代表已经被跟踪或无法跟踪  
      }  
      else  
      {  
          return -10201;    //其他错误(进程不存在或非法操作)  
      }  
  }  
  else  
  {  
      // ptrace附加目标进程pid成功，获取指定pid进程的内存模块基址  
      // 获取其它进程的内存模块基址，需要root权限  
      if(!(mem_file = open(mem, O_RDONLY)))  
      {  
        return -20402;      //打开错误  
      }  
  }  
    
  return mem_file;  
}  