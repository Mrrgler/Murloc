#pragma once


#ifdef KERNEL_SMT
#define kernel_lock(lock_flag)\
	while(atomic_flag_test_and_set(lock_flag) == true){\
	\
	}

#define kernel_unlock(lock_flag)\
	atomic_flag_clear(lock_flag)

#else
#define kernel_lock(lock_flag) 

#define kernel_unlock(lock_flag) 

#endif