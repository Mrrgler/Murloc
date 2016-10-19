
struct __attribute__((packed)) InterruptGateDescriptor{
	//uint16_t OffsetLow;
	uint32_t OffsetAndSegSelector;     // workaround of inability of ld to cast 32bit address to 16 bit in compile time
	//uint16_t SegSelector;
	uint16_t Flags;
	uint16_t OffsetHigh;
};


uint32_t InterruptsInit();