struct c_data{
	unsigned int p_number;
	unsigned int p_length;	
		}__attribute__((packed));

struct ak_data{
	unsigned char a_buffer[2048];
	unsigned int a_bytes;
	unsigned char a_hdr;
};

struct dir_iv{
	unsigned char base_iv[12];
	uint64_t counter;
};
