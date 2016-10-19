extern volatile uint8_t* pVideo; // vga video memory
void LogCritical(const char* pText, ...);
uint32_t printdw(char* buf, uint32_t data, uint32_t width);
uint32_t printdw_dec(char* buf, uint32_t data);


#ifdef KERNEL_DEBUG
#define LogDebug(...)\
	LogCritical(__VA_ARGS__);
#else
#define LogDebug(...) 
	
#endif


//#define