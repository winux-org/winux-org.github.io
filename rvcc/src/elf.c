/* rvcc C compiler - ELF file generator */

void e_write_footer_string(char *vals, int len)
{
	int i;
	for (i = 0; i < len; i++)
		_e_footer[_e_footer_idx++] = vals[i];
}

void e_write_data_string(char *vals, int len)
{
	int i;
	for (i = 0; i < len; i++)
		_e_data[_e_data_idx++] = vals[i];
}

void e_write_header_byte(int val)
{
	_e_header[_e_header_idx++] = val;
}

void e_write_footer_byte(char val)
{
	_e_footer[_e_footer_idx++] = val;
}

char e_extract_byte(int v, int b)
{
	return (v >> (b * 8)) & 0xFF;
}

int e_write_int(char *buf, int idx, int val)
{
	int i = 0;
	for (i = 0; i < 4; i++)
		buf[idx++] = e_extract_byte(val, i);
	return idx;
}

void e_write_header_int(int val)
{
	_e_header_idx = e_write_int(_e_header, _e_header_idx, val);
}

void e_write_footer_int(int val)
{
	_e_footer_idx = e_write_int(_e_footer, _e_footer_idx, val);
}

void e_write_symbol_int(int val)
{
	_e_symtab_idx = e_write_int(_e_symtab, _e_symtab_idx, val);
}

void e_write_code_int(int val)
{
	_e_code_idx = e_write_int(_e_code, _e_code_idx, val);
}

void e_write_data_byte(char val)
{
	_e_data[_e_data_idx++] = val;
}

void c_emit(int code)
{
	e_write_code_int(code);
}

void e_generate_header()
{
	/* ELF header */
	e_write_header_int(0x464c457f); /* ELF magic */
	e_write_header_byte(1); /* 32-bit */
	e_write_header_byte(1); /* little-endian */
	e_write_header_byte(1);
	e_write_header_byte(0); /* System V */
	e_write_header_int(0);
	e_write_header_int(0);
	e_write_header_byte(2); /* ET_EXEC */
	e_write_header_byte(0);
	e_write_header_byte(_backend->elf_machine());
	e_write_header_byte(0);
	e_write_header_int(1); /* ELF version */
	e_write_header_int(ELF_START + _e_header_len); /* entry point */
	e_write_header_int(0x34); /* program header offset */
	e_write_header_int(_e_header_len + _e_code_idx + _e_data_idx + 39 + _e_symtab_idx +
			   _e_strtab_idx); /* section header offset */
	/* flags */
	e_write_header_int(_backend->elf_flags());
	e_write_header_byte(0x34); /* header size */
	e_write_header_byte(0);
	e_write_header_byte(0x20); /* program header size */
	e_write_header_byte(0);
	e_write_header_byte(1); /* number of prog headers */
	e_write_header_byte(0);
	e_write_header_byte(0x28); /* section header size */
	e_write_header_byte(0);
	e_write_header_byte(6); /* number of sections */
	e_write_header_byte(0);
	e_write_header_byte(5); /* section index with names */
	e_write_header_byte(0);

	/* program header - code and data combined */
	e_write_header_int(1); /* PT_LOAD */
	e_write_header_int(_e_header_len); /* offset */
	e_write_header_int(ELF_START + _e_header_len); /* virtual address */
	e_write_header_int(ELF_START + _e_header_len); /* physical address */
	e_write_header_int(_e_code_idx + _e_data_idx); /* size in file */
	e_write_header_int(_e_code_idx + _e_data_idx); /* size in memory */
	e_write_header_int(7); /* flags */
	e_write_header_int(4); /* alignment */
}

void e_generate_footer()
{
	/* symtab section */
	int b;
	for (b = 0; b < _e_symtab_idx; b++)
		e_write_footer_byte(_e_symtab[b]);

	/* strtab section */
	for (b = 0; b < _e_strtab_idx; b++)
		e_write_footer_byte(_e_strtab[b]);

	/* shstr section; len = 39 */
	e_write_footer_byte(0);
	e_write_footer_string(".shstrtab", 9);
	e_write_footer_byte(0);
	e_write_footer_string(".text", 5);
	e_write_footer_byte(0);
	e_write_footer_string(".data", 5);
	e_write_footer_byte(0);
	e_write_footer_string(".symtab", 7);
	e_write_footer_byte(0);
	e_write_footer_string(".strtab", 7);
	e_write_footer_byte(0);

	/* section header table */

	/* NULL section */
	e_write_footer_int(0);
	e_write_footer_int(0);
	e_write_footer_int(0);
	e_write_footer_int(0);
	e_write_footer_int(0);
	e_write_footer_int(0);
	e_write_footer_int(0);
	e_write_footer_int(0);
	e_write_footer_int(0);
	e_write_footer_int(0);

	/* .text */
	e_write_footer_int(0xb);
	e_write_footer_int(1);
	e_write_footer_int(7);
	e_write_footer_int(ELF_START + _e_header_len);
	e_write_footer_int(_e_header_len);
	e_write_footer_int(_e_code_idx);
	e_write_footer_int(0);
	e_write_footer_int(0);
	e_write_footer_int(4);
	e_write_footer_int(0);

	/* .data */
	e_write_footer_int(0x11);
	e_write_footer_int(1);
	e_write_footer_int(3);
	e_write_footer_int(_e_code_start + _e_code_idx);
	e_write_footer_int(_e_header_len + _e_code_idx);
	e_write_footer_int(_e_data_idx);
	e_write_footer_int(0);
	e_write_footer_int(0);
	e_write_footer_int(4);
	e_write_footer_int(0);

	/* .symtab */
	e_write_footer_int(0x17);
	e_write_footer_int(2);
	e_write_footer_int(0);
	e_write_footer_int(0);
	e_write_footer_int(_e_header_len + _e_code_idx + _e_data_idx);
	e_write_footer_int(_e_symtab_idx); /* size */
	e_write_footer_int(4);
	e_write_footer_int(_e_symbol_idx);
	e_write_footer_int(4);
	e_write_footer_int(16);

	/* .strtab */
	e_write_footer_int(0x1f);
	e_write_footer_int(3);
	e_write_footer_int(0);
	e_write_footer_int(0);
	e_write_footer_int(_e_header_len + _e_code_idx + _e_data_idx + _e_symtab_idx);
	e_write_footer_int(_e_strtab_idx); /* size */
	e_write_footer_int(0);
	e_write_footer_int(0);
	e_write_footer_int(1);
	e_write_footer_int(0);

	/* .shstr */
	e_write_footer_int(1);
	e_write_footer_int(3);
	e_write_footer_int(0);
	e_write_footer_int(0);
	e_write_footer_int(_e_header_len + _e_code_idx + _e_data_idx + _e_symtab_idx + _e_strtab_idx);
	e_write_footer_int(39);
	e_write_footer_int(0);
	e_write_footer_int(0);
	e_write_footer_int(1);
	e_write_footer_int(0);
}

void e_align()
{
	int remainder = _e_data_idx & 3;
	if (remainder != 0)
		_e_data_idx += (4 - remainder);

	remainder = _e_symtab_idx & 3;
	if (remainder != 0)
		_e_symtab_idx += (4 - remainder);

	remainder = _e_strtab_idx & 3;
	if (remainder != 0)
		_e_strtab_idx += (4 - remainder);
}

void e_add_symbol(char *symbol, int len, int pc)
{
	e_write_symbol_int(_e_strtab_idx);
	e_write_symbol_int(pc);
	e_write_symbol_int(0);
	if (pc == 0)
		e_write_symbol_int(0);
	else
		e_write_symbol_int(1 << 16);

	strncpy(_e_strtab + _e_strtab_idx, symbol, len);
	_e_strtab_idx += len;
	_e_strtab[_e_strtab_idx++] = 0;
	_e_symbol_idx++;
}

void e_output(char *outfile)
{
	FILE *fp;
	int i;

	if (outfile == NULL)
		outfile = "out.elf";

	fp = fopen(outfile, "wb");
	for (i = 0; i < _e_header_idx; i++)
		fputc(_e_header[i], fp);
	for (i = 0; i < _e_code_idx; i++)
		fputc(_e_code[i], fp);
	for (i = 0; i < _e_data_idx; i++)
		fputc(_e_data[i], fp);
	for (i = 0; i < _e_footer_idx; i++)
		fputc(_e_footer[i], fp);
	fclose(fp);
}

void e_generate(char *outfile)
{
	e_align();
	e_generate_header();
	e_generate_footer();
	e_output(outfile);
}
