/* rvcc C compiler */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/* rvcc C compiler - definitions */

/* code limits */
#define MAX_TOKEN_LEN 256
#define MAX_ID_LEN 64
#define MAX_LINE_LEN 256
#define MAX_VAR_LEN 64
#define MAX_TYPE_LEN 64
#define MAX_PARAMS 8
#define MAX_LOCALS 64
#define MAX_FIELDS 64
#define MAX_FUNCTIONS 1024
#define MAX_BLOCKS 1048576
#define MAX_TYPES 64
#define MAX_IL 262144
#define MAX_SOURCE 1048576
#define MAX_CODE 1048576
#define MAX_DATA 1048576
#define MAX_SYMTAB 65536
#define MAX_STRTAB 65536
#define MAX_HEADER 1024
#define MAX_FOOTER 1024
#define MAX_ALIASES 1024
#define MAX_CONSTANTS 1024
#define MAX_CASES 128
#define MAX_NESTING 128

#define ELF_START 0x10000
#define PTR_SIZE 4

typedef enum { a_riscv, a_arm } arch_t;

/* builtin types */
typedef enum { bt_void = 0, bt_int = 1, bt_char = 2, bt_struct = 3 } base_type;

/* IL operation definitions */
typedef enum {
	/* generic - fixed assembly instruction */
	op_generic,
	/* function entry point */
	op_entry_point,
	/* retrieve address of a constant */
	op_load_data_address,
	/* program exit routine */
	op_exit,
	/* function call */
	op_function_call,
	/* pointer call */
	op_pointer_call,
	/* function exit code */
	op_exit_point,
	/* jump to function exit */
	op_return,
	/* unconditional jump */
	op_jump,
	/* load constant */
	op_load_numeric_constant,
	/* note label */
	op_label,
	/* jump if false */
	op_jz,
	/* jump if true */
	op_jnz,
	/* push onto stack */
	op_push,
	/* pop from stack */
	op_pop,
	/* code block start */
	op_block_start,
	/* code block end */
	op_block_end,
	/* lookup variable's address */
	op_get_var_addr,
	/* read from memory address */
	op_read_addr,
	/* write to memory address */
	op_write_addr,
	/* arithmetic operators */
	op_add,
	op_sub,
	op_mul,
	op_bit_lshift,
	op_bit_rshift,
	op_log_and,
	op_log_or,
	op_not,
	op_equals,
	op_not_equals,
	op_less_than,
	op_less_eq_than,
	op_greater_than,
	op_greater_eq_than,
	op_bit_or,
	op_bit_and,
	op_negate,
	op_syscall,
	op_start
} il_op;

/* IL instruction */
typedef struct {
	il_op op; /* IL operation */
	int op_len; /*    binary length */
	int il_index; /* index in IL list */
	int code_offset; /* offset in code */
	int param_no; /* destination */
	int int_param1;
	int int_param2;
	char *string_param1;
} il_instr;

/* variable definition */
typedef struct {
	char type_name[MAX_TYPE_LEN];
	char variable_name[MAX_VAR_LEN];
	int is_pointer;
	int is_function;
	int array_size;
	int offset; /* offset from stack or frame */
} variable_def;

/* function definition */
typedef struct {
	variable_def return_def;
	variable_def param_defs[MAX_PARAMS];
	int num_params;
	int entry_point; /* IL index */
	int exit_point; /* IL index */
	int params_size;
} function_def;

/* block definition */
typedef struct block_def {
	variable_def locals[MAX_LOCALS];
	int next_local;
	struct block_def *parent;
	function_def *function;
	int locals_size;
	int bd_index;
} block_def;

/* type definition */
typedef struct {
	char type_name[MAX_TYPE_LEN];
	base_type base_type;
	int size;
	variable_def fields[MAX_FIELDS];
	int num_fields;
} type_def;

/* lvalue details */
typedef struct {
	int size;
	int is_pointer;
	type_def *type;
} lvalue_def;

/* alias for #defines */
typedef struct {
	char alias[MAX_VAR_LEN];
	char value[MAX_VAR_LEN];
} alias_def;

/* constants for enums */
typedef struct defs {
	char alias[MAX_VAR_LEN];
	int value;
} constant_def;

typedef struct {
	int code_start;
	int data_start;
	int dest_reg;
	int op_reg;
	int pc;
} backend_state;

typedef struct {
	arch_t arch;
	char *source_define;
	int (*elf_machine)();
	int (*elf_flags)();
	int (*c_dest_reg)(int);
	int (*c_get_code_length)(il_instr *);
	void (*op_load_data_address)(backend_state *, int);
	void (*op_load_numeric_constant)(backend_state *, int);
	void (*op_get_global_addr)(backend_state *, int);
	void (*op_get_local_addr)(backend_state *, int);
	void (*op_get_function_addr)(backend_state *, int);
	void (*op_read_addr)(backend_state *, int);
	void (*op_write_addr)(backend_state *, int);
	void (*op_jump)(int);
	void (*op_return)(int);
	void (*op_function_call)(backend_state *, int);
	void (*op_pointer_call)(backend_state *);
	void (*op_push)(backend_state *);
	void (*op_pop)(backend_state *);
	void (*op_exit_point)();
	void (*op_alu)(backend_state *, il_op);
	void (*op_cmp)(backend_state *, il_op);
	void (*op_log)(backend_state *, il_op);
	void (*op_bit)(backend_state *, il_op);
	void (*op_jz)(backend_state *, il_op, int);
	void (*op_block)(int);
	void (*op_entry_point)(int);
	void (*op_store_param)(int, int);
	void (*op_start)();
	void (*op_syscall)();
	void (*op_exit)();
} backend_def;



/* rvcc C compiler - global structures */

block_def *_blocks;
int _blocks_idx;

function_def *_functions;
int _functions_idx;

type_def *_types;
int _types_idx;

il_instr *_il;
int _il_idx;

alias_def *_aliases;
int _aliases_idx;

constant_def *_constants;
int _constants_idx;

char *_source;
int _source_idx;
char _l_next_char;

int _c_block_level;
int _p_break_level;
int *_p_break_exit_il_idxs;

variable_def *_temp_variable;

backend_def *_backend;

/* ELF sections */

char *_e_code;
int _e_code_idx;
char *_e_data;
int _e_data_idx;
char *_e_symtab;
int _e_symtab_idx;
char *_e_strtab;
int _e_strtab_idx;
char *_e_header;
int _e_header_idx;
char *_e_footer;
int _e_footer_idx;
int _e_header_len;
int _e_code_start;
int _e_symbol_idx;

type_def *find_type(char *type_name)
{
	int i;
	for (i = 0; i < _types_idx; i++)
		if (strcmp(_types[i].type_name, type_name) == 0)
			return &_types[i];
	return NULL;
}

il_instr *add_instr(il_op op)
{
	il_instr *ii = &_il[_il_idx];
	ii->op = op;
	ii->op_len = 0;
	ii->string_param1 = 0;
	ii->il_index = _il_idx++;
	return ii;
}

il_instr *add_generic(int generic_op)
{
	il_instr *ii = &_il[_il_idx];
	ii->op = op_generic;
	ii->int_param1 = generic_op;
	ii->op_len = 0;
	ii->il_index = _il_idx++;
	return ii;
}

block_def *add_block(block_def *parent, function_def *function)
{
	block_def *bd = &_blocks[_blocks_idx];
	bd->bd_index = _blocks_idx++;
	bd->parent = parent;
	bd->function = function;
	bd->next_local = 0;
	return bd;
}

void add_alias(char *alias, char *value)
{
	alias_def *al = &_aliases[_aliases_idx++];
	strcpy(al->alias, alias);
	strcpy(al->value, value);
}

char *find_alias(char alias[])
{
	int i;
	for (i = 0; i < _aliases_idx; i++)
		if (strcmp(alias, _aliases[i].alias) == 0)
			return _aliases[i].value;
	return NULL;
}

function_def *add_function(char *name)
{
	function_def *fn;
	int i;

	/* return existing if found */
	for (i = 0; i < _functions_idx; i++)
		if (strcmp(_functions[i].return_def.variable_name, name) == 0)
			return &_functions[i];

	fn = &_functions[_functions_idx++];
	strcpy(fn->return_def.variable_name, name);
	return fn;
}

type_def *add_type()
{
	return &_types[_types_idx++];
}

type_def *add_named_type(char *name)
{
	type_def *type = add_type();
	strcpy(type->type_name, name);
	return type;
}

void add_constant(char alias[], int value)
{
	constant_def *constant = &_constants[_constants_idx++];
	strcpy(constant->alias, alias);
	constant->value = value;
}

constant_def *find_constant(char alias[])
{
	int i;
	for (i = 0; i < _constants_idx; i++)
		if (strcmp(_constants[i].alias, alias) == 0)
			return &_constants[i];
	return NULL;
}

function_def *find_function(char function_name[])
{
	int i;
	for (i = 0; i < _functions_idx; i++)
		if (strcmp(_functions[i].return_def.variable_name, function_name) == 0)
			return &_functions[i];
	return NULL;
}

variable_def *find_member(char token[], type_def *type)
{
	int i;
	for (i = 0; i < type->num_fields; i++)
		if (strcmp(type->fields[i].variable_name, token) == 0)
			return &type->fields[i];
	return NULL;
}

variable_def *find_local_variable(char *token, block_def *block)
{
	int i;
	function_def *fn = block->function;

	while (block != NULL) {
		for (i = 0; i < block->next_local; i++)
			if (strcmp(block->locals[i].variable_name, token) == 0)
				return &block->locals[i];
		block = block->parent;
	}

	if (fn != NULL) {
		for (i = 0; i < fn->num_params; i++)
			if (strcmp(fn->param_defs[i].variable_name, token) == 0)
				return &fn->param_defs[i];
	}
	return NULL;
}

variable_def *find_global_variable(char *token)
{
	int i;
	block_def *block = &_blocks[0];

	for (i = 0; i < block->next_local; i++)
		if (strcmp(block->locals[i].variable_name, token) == 0)
			return &block->locals[i];
	return NULL;
}

variable_def *find_variable(char *token, block_def *parent)
{
	variable_def *var = find_local_variable(token, parent);
	if (var == NULL)
		var = find_global_variable(token);
	return var;
}

int size_variable(variable_def *var)
{
	type_def *td;
	int bs, j, s = 0;

	if (var->is_pointer > 0 || var->is_function > 0) {
		s += 4;
	} else {
		td = find_type(var->type_name);
		bs = td->size;
		if (var->array_size > 0) {
			for (j = 0; j < var->array_size; j++)
				s += bs;
		} else
			s += bs;
	}
	return s;
}

void g_initialize()
{
	_e_header_len = 0x54; /* ELF fixed: 0x34 + 1 * 0x20 */

	_e_header_idx = 0;
	_e_footer_idx = 0;
	_e_code_idx = 0;
	_e_data_idx = 0;
	_il_idx = 0;
	_source_idx = 0;
	_e_strtab_idx = 0;
	_e_symtab_idx = 0;
	_aliases_idx = 0;
	_constants_idx = 0;
	_blocks_idx = 0;
	_types_idx = 0;
	_functions_idx = 0;
	_p_break_level = 0;
	_e_symbol_idx = 0;

	_e_code_start = ELF_START + _e_header_len;

	_functions = malloc(MAX_FUNCTIONS * sizeof(function_def));
	_blocks = malloc(MAX_BLOCKS * sizeof(block_def));
	_types = malloc(MAX_TYPES * sizeof(type_def));
	_il = malloc(MAX_IL * sizeof(il_instr));
	_source = malloc(MAX_SOURCE);
	_e_code = malloc(MAX_CODE);
	_e_data = malloc(MAX_DATA);
	_e_symtab = malloc(MAX_SYMTAB);
	_e_strtab = malloc(MAX_STRTAB);
	_e_header = malloc(MAX_HEADER);
	_e_footer = malloc(MAX_FOOTER);
	_aliases = malloc(MAX_ALIASES * sizeof(alias_def));
	_constants = malloc(MAX_CONSTANTS * sizeof(constant_def));
	_temp_variable = malloc(sizeof(variable_def));
	_p_break_exit_il_idxs = malloc(MAX_NESTING * sizeof(int));
	_backend = malloc(sizeof(backend_def));
}

void error(char *msg)
{
	printf("Error %s at source location %d, IL index %d\n", msg, _source_idx, _il_idx);
	abort();
}

/* rvcc C compiler - misc helpers */

int is_whitespace(char c)
{
	if (c == ' ' || c == '\r' || c == '\n' || c == '\t')
		return 1;
	return 0;
}

int is_alnum(char c)
{
	if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || (c == '_'))
		return 1;
	return 0;
}

int is_digit(char c)
{
	if (c >= '0' && c <= '9')
		return 1;
	return 0;
}

int is_hex(char c)
{
	if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || c == 'x' || (c >= 'A' && c <= 'F'))
		return 1;
	return 0;
}




/* rvcc C compiler - source code loader */

void s_write_string(char *src)
{
	int i = 0;
	while (src[i] != 0) {
		_source[_source_idx++] = src[i];
		i++;
	}
}

/* shortcut for embedding */
void __s(char *src)
{
	s_write_string(src);
}

void s_load(char *file)
{
	FILE *f;
	char buffer[MAX_LINE_LEN];

	printf("Loading source file %s\n", file);

	f = fopen(file, "rb");
	for (;;) {
		if (fgets(buffer, MAX_LINE_LEN, f) == NULL) {
			fclose(f);
			return;
		}
		if (strncmp(buffer, "#include ", 9) == 0 && buffer[9] == '"') {
			char path[MAX_LINE_LEN];
			int c = strlen(file) - 1;
			while (c > 0 && file[c] != '/')
				c--;
			if (c != 0) {
				/* prepend directory name */
				strncpy(path, file, c + 1);
				c++;
			}
			path[c] = 0;
			buffer[strlen(buffer) - 2] = 0;
			strcpy(path + c, buffer + 10);
			s_load(path);
		} else {
			strcpy(_source + _source_idx, buffer);
			_source_idx += strlen(buffer);
		}
	}
	fclose(f);
}


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

/* rvcc C compiler - IL->binary code generator */

/* calculates stack space needed for function's parameters */
void c_size_function(function_def *fn)
{
	int s = 0, i;

	/* parameters are turned into local variables */
	for (i = 0; i < fn->num_params; i++) {
		int vs = size_variable(&fn->param_defs[i]);
		fn->param_defs[i].offset = s + vs; /* set stack offset */
		s += vs;
	}

	/* align to 16 bytes */
	if ((s & 15) > 0)
		s = (s - (s & 15)) + 16;
	if (s > 2047)
		error("Local stack size exceeded");

	fn->params_size = s;
}

/* returns stack size required after block local variables */
int c_size_block(block_def *bd)
{
	int size = 0, i, offset;

	/* our offset starts from parent's offset */
	if (bd->parent == NULL)
		if (bd->function != NULL)
			offset = bd->function->params_size;
		else
			offset = 0;
	else
		offset = c_size_block(bd->parent);

	/* declared locals */
	for (i = 0; i < bd->next_local; i++) {
		int vs = size_variable(&bd->locals[i]);
		bd->locals[i].offset = size + offset + vs; /* for looking up value off stack */
		size += vs;
	}

	/* align to 16 bytes */
	if ((size & 15) > 0)
		size = (size - (size & 15)) + 16;
	if (size > 2047)
		error("Local stack size exceeded");

	bd->locals_size = size; /* save in block for stack allocation */
	return size + offset;
}

/* calculate stack necessary sizes for all functions */
void c_size_functions(int data_start)
{
	block_def *bd;
	int i;

	/* size functions */
	for (i = 0; i < _functions_idx; i++)
		c_size_function(&_functions[i]);

	/* size blocks excl. global block */
	for (i = 1; i < _blocks_idx; i++)
		c_size_block(&_blocks[i]);

	/* allocate data for globals, in block 0 */
	bd = &_blocks[0];
	for (i = 0; i < bd->next_local; i++) {
		bd->locals[i].offset = _e_data_idx; /* set offset in data section */
		e_add_symbol(bd->locals[i].variable_name, strlen(bd->locals[i].variable_name),
			     data_start + _e_data_idx);
		_e_data_idx += size_variable(&bd->locals[i]);
	}
}

/* calculates total binary code length based on IL ops */
int c_calculate_code_length()
{
	int code_len = 0, i;
	for (i = 0; i < _il_idx; i++) {
		_il[i].code_offset = code_len;
		_il[i].op_len = _backend->c_get_code_length(&_il[i]);
		code_len += _il[i].op_len;
	}
	return code_len;
}

/* main code generation loop */
void c_generate()
{
	int i;
	int stack_size = 0;
	block_def *bd = NULL;

	backend_state state;
	state.code_start = _e_code_start; /* ELF headers size */
	state.data_start = c_calculate_code_length();
	c_size_functions(state.code_start + state.data_start);

	for (i = 0; i < _il_idx; i++) {
		int j;
		int offset, ofs, val;
		variable_def *var;
		function_def *fn;

		il_instr *ii = &_il[i];
		il_op op = ii->op;
		state.pc = _e_code_idx;
		state.dest_reg = _backend->c_dest_reg(ii->param_no);
		state.op_reg = _backend->c_dest_reg(ii->int_param1);

		/* format IL log prefix */
		printf("%4d %3d  %#010x     ", i, op, state.code_start + state.pc);
		for (j = 0; j < _c_block_level; j++)
			printf("  ");

		switch (op) {
		case op_load_data_address:
			/* lookup address of a constant in data section */
			ofs = state.data_start + ii->int_param1;
			_backend->op_load_data_address(&state, ofs);
			printf("  x%d := &data[%d]", state.dest_reg, ii->int_param1);
			break;
		case op_load_numeric_constant:
			/* load numeric constant */
			val = ii->int_param1;
			_backend->op_load_numeric_constant(&state, val);
			printf("  x%d := %d", state.dest_reg, ii->int_param1);
			break;
		case op_get_var_addr:
			/* lookup address of a variable */
			var = find_global_variable(ii->string_param1);
			if (var != NULL) {
				int ofs = state.data_start + var->offset;
				_backend->op_get_global_addr(&state, ofs);
			} else {
				/* need to find the variable offset on stack, i.e. from s0 */
				var = find_local_variable(ii->string_param1, bd);
				if (var != NULL) {
					offset = -var->offset;
					_backend->op_get_local_addr(&state, offset);
				} else {
					/* is it function address? */
					fn = find_function(ii->string_param1);
					if (fn != NULL) {
						int jump_instr_index = fn->entry_point;
						il_instr *jump_instr = &_il[jump_instr_index];
						ofs = state.code_start +
						      jump_instr->code_offset; /* load code offset into variable */
						_backend->op_get_function_addr(&state, ofs);
					} else
						error("Undefined identifier");
				}
			}
			printf("  x%d = &%s", state.dest_reg, ii->string_param1);
			break;
		case op_read_addr:
			/* read (dereference) memory address */
			_backend->op_read_addr(&state, ii->int_param2);
			printf("  x%d = *x%d (%d)", state.dest_reg, state.op_reg, ii->int_param2);
			break;
		case op_write_addr:
			/* write at memory address */
			_backend->op_write_addr(&state, ii->int_param2);
			printf("  *x%d = x%d (%d)", state.op_reg, state.dest_reg, ii->int_param2);
			break;
		case op_jump: {
			/* unconditional jump to an IL-index */
			int jump_instr_index = ii->int_param1;
			il_instr *jump_instr = &_il[jump_instr_index];
			int jump_location = jump_instr->code_offset;
			ofs = jump_location - state.pc;
			_backend->op_jump(ofs);
			printf("  -> %d", ii->int_param1);
		} break;
		case op_return: {
			/* jump to function exit */
			function_def *fd = find_function(ii->string_param1);
			int jump_instr_index = fd->exit_point;
			il_instr *jump_instr = &_il[jump_instr_index];
			int jump_location = jump_instr->code_offset;
			ofs = jump_location - state.pc;
			_backend->op_return(ofs);
			printf("  return %s", ii->string_param1);
		} break;
		case op_function_call: {
			/* function call */
			int jump_instr_index;
			il_instr *jump_instr;
			int jump_location;

			/* need to find offset */
			fn = find_function(ii->string_param1);
			jump_instr_index = fn->entry_point;
			jump_instr = &_il[jump_instr_index];
			jump_location = jump_instr->code_offset;
			ofs = jump_location - state.pc;

			_backend->op_function_call(&state, ofs);
			printf("  x%d := %s() @ %d", state.dest_reg, ii->string_param1, fn->entry_point);
		} break;
		case op_pointer_call: {
			/* function pointer call, address in op_reg, result in dest_reg */
			_backend->op_pointer_call(&state);
			printf("  x%d := x%d()", state.dest_reg, state.op_reg);
		} break;
		case op_push:
			_backend->op_push(&state);
			printf("  push x%d", state.dest_reg);
			break;
		case op_pop:
			_backend->op_pop(&state);
			printf("  pop x%d", state.dest_reg);
			break;
		case op_exit_point:
			/* restore previous frame */
			_backend->op_exit_point();
			fn = NULL;
			printf("  exit %s", ii->string_param1);
			break;
		case op_add:
			_backend->op_alu(&state, op_add);
			printf("  x%d += x%d", state.dest_reg, state.op_reg);
			break;
		case op_sub:
			_backend->op_alu(&state, op_sub);
			printf("  x%d -= x%d", state.dest_reg, state.op_reg);
			break;
		case op_mul:
			_backend->op_alu(&state, op_mul);
			printf("  x%d *= x%d", state.dest_reg, state.op_reg);
			break;
		case op_negate:
			_backend->op_alu(&state, op_negate);
			printf("  -x%d", state.dest_reg);
			break;
		case op_label:
			if (ii->string_param1 != NULL)
				/* TODO: lazy eval */
				if (strlen(ii->string_param1) > 0)
					e_add_symbol(ii->string_param1, strlen(ii->string_param1),
						     state.code_start + state.pc);
			printf(" _:");
			break;
		case op_equals:
		case op_not_equals:
		case op_less_than:
		case op_less_eq_than:
		case op_greater_than:
		case op_greater_eq_than:
			/* we want 1/nonzero if equ, 0 otherwise */
			_backend->op_cmp(&state, op);
			switch (op) {
			case op_equals:
				printf("  x%d == x%d ?", state.dest_reg, state.op_reg);
				break;
			case op_not_equals:
				printf("  x%d != x%d ?", state.dest_reg, state.op_reg);
				break;
			case op_less_than:
				printf("  x%d < x%d ?", state.dest_reg, state.op_reg);
				break;
			case op_greater_eq_than:
				printf("  x%d >= x%d ?", state.dest_reg, state.op_reg);
				break;
			case op_greater_than:
				printf("  x%d > x%d ?", state.dest_reg, state.op_reg);
				break;
			case op_less_eq_than:
				printf("  x%d <= x%d ?", state.dest_reg, state.op_reg);
				break;
			default:
				break;
			}
			break;
		case op_log_and:
			_backend->op_log(&state, op);
			printf("  x%d &&= x%d", state.dest_reg, state.op_reg);
			break;
		case op_log_or:
			_backend->op_log(&state, op);
			printf("  x%d ||= x%d", state.dest_reg, state.op_reg);
			break;
		case op_bit_and:
			_backend->op_bit(&state, op);
			printf("  x%d &= x%d", state.dest_reg, state.op_reg);
			break;
		case op_bit_or:
			_backend->op_bit(&state, op);
			printf("  x%d |= x%d", state.dest_reg, state.op_reg);
			break;
		case op_bit_lshift:
			_backend->op_bit(&state, op);
			printf("  x%d <<= x%d", state.dest_reg, state.op_reg);
			break;
		case op_bit_rshift:
			_backend->op_bit(&state, op);
			printf("  x%d >>= x%d", state.dest_reg, state.op_reg);
			break;
		case op_not:
			/* 1 if zero, 0 if nonzero */
			_backend->op_bit(&state, op);
			printf("  !x%d", state.dest_reg);
			break;
		case op_jz:
		case op_jnz: {
			/* conditional jumps to IL-index */
			int jump_instr_index = ii->int_param1;
			il_instr *jump_instr = &_il[jump_instr_index];
			int jump_location = jump_instr->code_offset;
			int ofs = jump_location - state.pc - 4;
			_backend->op_jz(&state, op, ofs);
			if (op == op_jz)
				printf("  if 0 -> %d", ii->int_param1);
			else
				printf("  if 1 -> %d", ii->int_param1);
		} break;
		case op_generic:
			c_emit(ii->int_param1);
			printf("  asm %#010x", ii->int_param1);
			break;
		case op_block_start:
			bd = &_blocks[ii->int_param1];
			if (bd->next_local > 0) {
				/* reserve stack space for locals */
				_backend->op_block(-bd->locals_size);
				stack_size += bd->locals_size;
			}
			printf("  {");
			_c_block_level++;
			break;
		case op_block_end:
			bd = &_blocks[ii->int_param1]; /* should not be necessarry */
			if (bd->next_local > 0) {
				/* remove stack space for locals */
				_backend->op_block(bd->locals_size);
				stack_size -= bd->locals_size;
			}
			/* bd is current block */
			bd = bd->parent;
			printf("}");
			_c_block_level--;
			break;
		case op_entry_point: {
			int pn, ps;
			fn = find_function(ii->string_param1);
			ps = fn->params_size;

			/* add to symbol table */
			e_add_symbol(ii->string_param1, strlen(ii->string_param1), state.code_start + state.pc);

			/* create stack space for params and parent frame */
			_backend->op_entry_point(ps);
			stack_size = ps;

			/* push parameters on stack */
			for (pn = 0; pn < fn->num_params; pn++) {
				_backend->op_store_param(pn, -fn->param_defs[pn].offset);
			}
			printf("%s:", ii->string_param1);
		} break;
		case op_start:
			_backend->op_start();
			printf("  start");
			break;
		case op_syscall:
			_backend->op_syscall();
			printf("  syscall");
			break;
		case op_exit:
			_backend->op_exit();
			printf("  exit");
			break;
		default:
			error("Unsupported IL op");
		}
		printf("\n");
	}

	printf("Finished code generation\n");
}


/* embedded clib */
/* #include "rvclib.inc" */


/* rvcc C compiler - source->IL parser */

void p_read_function_call(function_def *fn, int param_no, block_def *parent);
void p_read_lvalue(lvalue_def *lvalue, variable_def *var, block_def *parent, int param_no, int evaluate,
		   il_op prefix_op);
void p_read_expression(int param_no, block_def *parent);
void p_read_code_block(function_def *function, block_def *parent);
int p_read_parameter_list_declaration(variable_def vds[], int anon);
void p_read_function_parameters(block_def *parent);




















/* rvcc C compiler - lexer */

/* lexer tokens */
typedef enum {
	t_sof,
	t_numeric,
	t_identifier,
	t_comma,
	t_string,
	t_char,
	t_op_bracket,
	t_cl_bracket,
	t_op_curly,
	t_cl_curly,
	t_op_square,
	t_cl_square,
	t_star,
	t_bit_or,
	t_log_and,
	t_log_or,
	t_log_not,
	t_lt,
	t_gt,
	t_le,
	t_ge,
	t_lshift,
	t_rshift,
	t_dot,
	t_arrow,
	t_plus,
	t_minus,
	t_minuseq,
	t_pluseq,
	t_oreq,
	t_andeq,
	t_eq,
	t_noteq,
	t_assign,
	t_plusplus,
	t_minusminus,
	t_colon,
	t_semicolon,
	t_eof,
	t_ampersand,
	t_return,
	t_if,
	t_else,
	t_while,
	t_for,
	t_do,
	t_op_comment,
	t_cl_comment,
	t_define,
	t_include,
	t_typedef,
	t_enum,
	t_struct,
	t_sizeof,
	t_elipsis,
	t_asm,
	t_switch,
	t_case,
	t_break,
	t_default
} l_token;

char _l_token_string[MAX_TOKEN_LEN];
l_token _l_next_token;

void l_skip_whitespace()
{
	while (is_whitespace(_l_next_char)) {
		_l_next_char = _source[++_source_idx];
	}
}

char l_read_char(int skip_whitespace)
{
	_l_next_char = _source[++_source_idx];
	if (skip_whitespace == 1)
		l_skip_whitespace();
	return _l_next_char;
}

int l_read_alnum(char *buffer, int max_len)
{
	int bi = 0;
	while (is_alnum(l_read_char(0))) {
		buffer[bi++] = _l_next_char;
		if (bi >= max_len)
			error("Length exceeded");
	}
	buffer[bi] = 0;
	return bi;
}

l_token l_next_token()
{
	_l_token_string[0] = 0;
	if (_l_next_char == '#') {
		int i = 0;
		do {
			_l_token_string[i++] = _l_next_char;
		} while (is_alnum(l_read_char(0)));
		_l_token_string[i] = 0;
		l_skip_whitespace();

		if (strcmp(_l_token_string, "#include") == 0) {
			i = 0;
			do {
				_l_token_string[i++] = _l_next_char;
			} while (l_read_char(0) != '\n');
			l_skip_whitespace();
			return t_include;
		}
		if (strcmp(_l_token_string, "#define") == 0) {
			l_skip_whitespace();
			return t_define;
		}
		if (strcmp(_l_token_string, "#ifdef") == 0) {
			i = 0;
			do {
				_l_token_string[i++] = _l_next_char;
			} while (l_read_char(0) != '\n');
			_l_token_string[i] = 0;
			/* check if we have this alias/define */
			for (i = 0; i < _aliases_idx; i++) {
				if (strcmp(_l_token_string, _aliases[i].alias) == 0) {
					l_skip_whitespace();
					return l_next_token();
				}
			}
			/* skip lines until #endif */
			do {
				l_skip_whitespace();
				i = 0;
				do {
					_l_token_string[i++] = _l_next_char;
				} while (l_read_char(0) != '\n');
				_l_token_string[i] = 0;
			} while (strcmp(_l_token_string, "#endif") != 0);
			l_skip_whitespace();
			return l_next_token();
		}
		if (strcmp(_l_token_string, "#endif") == 0) {
			l_skip_whitespace();
			return l_next_token();
		}
		error("Unknown directive");
	}
	if (_l_next_char == '/') {
		l_read_char(0);
		if (_l_next_char == '*') {
			/* we are in a comment, skip until end */
			do {
				l_read_char(0);
				if (_l_next_char == '*') {
					l_read_char(0);
					if (_l_next_char == '/') {
						l_read_char(1);
						return l_next_token();
					}
				}
			} while (_l_next_char != 0);
		}
		error("Unexpected '/'"); /* invalid otherwise? */
	}

	if (is_digit(_l_next_char)) {
		int i = 0;
		do {
			_l_token_string[i++] = _l_next_char;
		} while (is_hex(l_read_char(0)));
		_l_token_string[i] = 0;
		l_skip_whitespace();
		return t_numeric;
	}
	if (_l_next_char == '(') {
		l_read_char(1);
		return t_op_bracket;
	}
	if (_l_next_char == ')') {
		l_read_char(1);
		return t_cl_bracket;
	}
	if (_l_next_char == '{') {
		l_read_char(1);
		return t_op_curly;
	}
	if (_l_next_char == '}') {
		l_read_char(1);
		return t_cl_curly;
	}
	if (_l_next_char == '[') {
		l_read_char(1);
		return t_op_square;
	}
	if (_l_next_char == ']') {
		l_read_char(1);
		return t_cl_square;
	}
	if (_l_next_char == ',') {
		l_read_char(1);
		return t_comma;
	}
	if (_l_next_char == '"') {
		int i = 0;
		int special = 0;

		while (l_read_char(0) != '"' || special) {
			if (i > 0 && _l_token_string[i - 1] == '\\') {
				if (_l_next_char == 'n')
					_l_token_string[i - 1] = '\n';
				else if (_l_next_char == '"')
					_l_token_string[i - 1] = '"';
				else if (_l_next_char == 'r')
					_l_token_string[i - 1] = '\r';
				else if (_l_next_char == '\'')
					_l_token_string[i - 1] = '\'';
				else if (_l_next_char == 't')
					_l_token_string[i - 1] = '\t';
				else if (_l_next_char == '\\')
					_l_token_string[i - 1] = '\\';
				else
					abort();
			} else {
				_l_token_string[i++] = _l_next_char;
			}
			if (_l_next_char == '\\')
				special = 1;
			else
				special = 0;
		}
		_l_token_string[i] = 0;
		l_read_char(1);
		return t_string;
	}
	if (_l_next_char == '\'') {
		l_read_char(0);
		if (_l_next_char == '\\') {
			l_read_char(0);
			if (_l_next_char == 'n')
				_l_token_string[0] = '\n';
			else if (_l_next_char == 'r')
				_l_token_string[0] = '\r';
			else if (_l_next_char == '\'')
				_l_token_string[0] = '\'';
			else if (_l_next_char == '"')
				_l_token_string[0] = '"';
			else if (_l_next_char == 't')
				_l_token_string[0] = '\t';
			else if (_l_next_char == '\\')
				_l_token_string[0] = '\\';
			else
				abort();
		} else {
			_l_token_string[0] = _l_next_char;
		}
		_l_token_string[1] = 0;
		if (l_read_char(0) != '\'')
			abort();
		l_read_char(1);
		return t_char;
	}
	if (_l_next_char == '*') {
		l_read_char(1);
		return t_star;
	}
	if (_l_next_char == '&') {
		l_read_char(0);
		if (_l_next_char == '&') {
			l_read_char(1);
			return t_log_and;
		};
		if (_l_next_char == '=') {
			l_read_char(1);
			return t_andeq;
		}
		l_skip_whitespace();
		return t_ampersand;
	}
	if (_l_next_char == '|') {
		l_read_char(0);
		if (_l_next_char == '|') {
			l_read_char(1);
			return t_log_or;
		};
		if (_l_next_char == '=') {
			l_read_char(1);
			return t_oreq;
		}
		l_skip_whitespace();
		return t_bit_or;
	}
	if (_l_next_char == '<') {
		l_read_char(0);
		if (_l_next_char == '=') {
			l_read_char(1);
			return t_le;
		};
		if (_l_next_char == '<') {
			l_read_char(1);
			return t_lshift;
		};
		l_skip_whitespace();
		return t_lt;
	}
	if (_l_next_char == '>') {
		l_read_char(0);
		if (_l_next_char == '=') {
			l_read_char(1);
			return t_ge;
		};
		if (_l_next_char == '>') {
			l_read_char(1);
			return t_rshift;
		};
		l_skip_whitespace();
		return t_gt;
	}
	if (_l_next_char == '!') {
		l_read_char(0);
		if (_l_next_char == '=') {
			l_read_char(1);
			return t_noteq;
		}
		l_skip_whitespace();
		return t_log_not;
	}
	if (_l_next_char == '.') {
		l_read_char(0);
		if (_l_next_char == '.') {
			l_read_char(0);
			if (_l_next_char == '.') {
				l_read_char(1);
				return t_elipsis;
			} else {
				abort();
			}
		}
		l_skip_whitespace();
		return t_dot;
	}
	if (_l_next_char == '-') {
		l_read_char(0);
		if (_l_next_char == '>') {
			l_read_char(1);
			return t_arrow;
		}
		if (_l_next_char == '-') {
			l_read_char(1);
			return t_minusminus;
		}
		if (_l_next_char == '=') {
			l_read_char(1);
			return t_minuseq;
		}
		l_skip_whitespace();
		return t_minus;
	}
	if (_l_next_char == '+') {
		l_read_char(0);
		if (_l_next_char == '+') {
			l_read_char(1);
			return t_plusplus;
		}
		if (_l_next_char == '=') {
			l_read_char(1);
			return t_pluseq;
		}
		l_skip_whitespace();
		return t_plus;
	}
	if (_l_next_char == ';') {
		l_read_char(1);
		return t_semicolon;
	}
	if (_l_next_char == ':') {
		l_read_char(1);
		return t_colon;
	}
	if (_l_next_char == '=') {
		l_read_char(0);
		if (_l_next_char == '=') {
			l_read_char(1);
			return t_eq;
		}
		l_skip_whitespace();
		return t_assign;
	}
	if (_l_next_char == 0 || _l_next_char == -1) {
		return t_eof;
	}
	if (is_alnum(_l_next_char)) {
		char *alias;
		int i = 0;
		do {
			_l_token_string[i++] = _l_next_char;
		} while (is_alnum(l_read_char(0)));
		_l_token_string[i] = 0;
		l_skip_whitespace();

		if (strcmp(_l_token_string, "if") == 0)
			return t_if;
		if (strcmp(_l_token_string, "while") == 0)
			return t_while;
		if (strcmp(_l_token_string, "for") == 0)
			return t_for;
		if (strcmp(_l_token_string, "do") == 0)
			return t_do;
		if (strcmp(_l_token_string, "else") == 0)
			return t_else;
		if (strcmp(_l_token_string, "return") == 0)
			return t_return;
		if (strcmp(_l_token_string, "typedef") == 0)
			return t_typedef;
		if (strcmp(_l_token_string, "enum") == 0)
			return t_enum;
		if (strcmp(_l_token_string, "struct") == 0)
			return t_struct;
		if (strcmp(_l_token_string, "sizeof") == 0)
			return t_sizeof;
		if (strcmp(_l_token_string, "switch") == 0)
			return t_switch;
		if (strcmp(_l_token_string, "case") == 0)
			return t_case;
		if (strcmp(_l_token_string, "break") == 0)
			return t_break;
		if (strcmp(_l_token_string, "default") == 0)
			return t_default;
		if (strcmp(_l_token_string, "#define") == 0)
			return t_define;
		if (strcmp(_l_token_string, "#include") == 0)
			return t_include;
		if (strcmp(_l_token_string, "_asm") == 0)
			return t_asm;

		alias = find_alias(_l_token_string);
		if (alias != NULL) {
			strcpy(_l_token_string, alias);
			return t_numeric;
		}

		return t_identifier;
	}
	error("Unrecognized input");
	return t_eof;
}

int l_accept(l_token token)
{
	if (_l_next_token == token) {
		_l_next_token = l_next_token();
		return 1;
	}
	return 0;
}

int l_peek(l_token token, char *value)
{
	if (_l_next_token == token) {
		if (value == NULL)
			return 1;
		strcpy(value, _l_token_string);
		return 1;
	}
	return 0;
}

void l_ident(l_token token, char *value)
{
	if (_l_next_token != token)
		error("Unexpected token");
	strcpy(value, _l_token_string);
	_l_next_token = l_next_token();
}

void l_expect(l_token token)
{
	if (_l_next_token != token)
		error("Unexpected token");
	_l_next_token = l_next_token();
}

void l_initialize()
{
	_source_idx = 0;
	_l_next_char = _source[0];
	l_expect(t_sof);
}





int p_write_symbol(char *data, int len)
{
	int startLen = _e_data_idx;
	e_write_data_string(data, len);
	return startLen;
}

int p_get_size(variable_def *var, type_def *type)
{
	if (var->is_pointer || var->is_function)
		return PTR_SIZE;
	return type->size;
}

void p_initialize()
{
	il_instr *ii;
	type_def *type;
	function_def *fn;

	/* built-in types */
	type = add_named_type("void");
	type->base_type = bt_void;
	type->size = 0;

	type = add_named_type("char");
	type->base_type = bt_char;
	type->size = 1;

	type = add_named_type("int");
	type->base_type = bt_int;
	type->size = 4;

	add_block(NULL, NULL); /* global block */
	e_add_symbol("", 0, 0); /* undef symbol */

	/* architecture defines */
	add_alias(_backend->source_define, "1");

	/* binary entry point: read params, call main, exit */
	ii = add_instr(op_label);
	ii->string_param1 = "__start";
	add_instr(op_start);
	ii = add_instr(op_function_call);
	ii->string_param1 = "main";
	ii = add_instr(op_label);
	ii->string_param1 = "__exit";
	add_instr(op_exit);

	/* Linux syscall */
	fn = add_function("__syscall");
	fn->num_params = 0;
	ii = add_instr(op_entry_point);
	fn->entry_point = ii->il_index;
	ii->string_param1 = fn->return_def.variable_name;
	ii = add_instr(op_syscall);
	ii->string_param1 = fn->return_def.variable_name;
	ii = add_instr(op_exit_point);
	ii->string_param1 = fn->return_def.variable_name;
	fn->exit_point = ii->il_index;
}

int p_read_numeric_constant(char buffer[])
{
	int i = 0;
	int value = 0;
	while (buffer[i] != 0) {
		if (i == 1 && (buffer[i] == 'x' || buffer[i] == 'X')) {
			value = 0;
			i = 2;
			while (buffer[i] != 0) {
				char c = buffer[i++];
				value = value << 4;
				if (c >= '0' && c <= '9')
					value += c - '0';
				else if (c >= 'a' && c <= 'f')
					value += c - 'a' + 10;
				else if (c >= 'A' && c <= 'F')
					value += c - 'A' + 10;
			}
			return value;
		}
		value = value * 10 + buffer[i++] - '0';
	}
	return value;
}

void p_read_inner_variable_declaration(variable_def *vd, int anon)
{
	if (l_accept(t_star))
		vd->is_pointer = 1;
	else
		vd->is_pointer = 0;

	/* is it function pointer declaration? */
	if (l_accept(t_op_bracket)) {
		variable_def funargs[MAX_PARAMS];
		l_expect(t_star);
		l_ident(t_identifier, vd->variable_name);
		l_expect(t_cl_bracket);
		p_read_parameter_list_declaration(funargs, 1);
		vd->is_function = 1;
	} else {
		if (anon == 0) {
			l_ident(t_identifier, vd->variable_name);
		}
		if (l_accept(t_op_square)) {
			char buffer[10];

			/* array with size*/
			if (l_peek(t_numeric, buffer)) {
				vd->array_size = p_read_numeric_constant(buffer);
				l_expect(t_numeric);
			} else {
				/* array without size - just a pointer although could be nested */
				vd->is_pointer++;
			}
			l_expect(t_cl_square);
		} else {
			vd->array_size = 0;
		}
	}
}

/* we are starting it _l_next_token, need to check the type */
void p_read_full_variable_declaration(variable_def *vd, int anon)
{
	l_accept(t_struct); /* ignore struct def */
	l_ident(t_identifier, vd->type_name);
	p_read_inner_variable_declaration(vd, anon);
}

/* we are starting it _l_next_token, need to check the type */
void p_read_partial_variable_declaration(variable_def *vd, variable_def *template)
{
	strcpy(vd->type_name, template->type_name);
	p_read_inner_variable_declaration(vd, 0);
}

int p_read_parameter_list_declaration(variable_def vds[], int anon)
{
	int vn = 0;
	l_expect(t_op_bracket);
	while (l_peek(t_identifier, NULL) == 1) {
		p_read_full_variable_declaration(&vds[vn++], anon);
		l_accept(t_comma);
	}
	if (l_accept(t_elipsis)) {
		/* variadic function - max 8 params total, create dummy parameters to put all on stack  */
		for (; vn < MAX_PARAMS; vn++) {
			strcpy(vds[vn].type_name, "int");
			strcpy(vds[vn].variable_name, "var_arg");
			vds[vn].is_pointer = 1;
		}
	}
	l_expect(t_cl_bracket);
	return vn;
}

void p_read_literal_param(int param_no)
{
	char literal[MAX_TOKEN_LEN];
	il_instr *ii;
	int didx;

	l_ident(t_string, literal);

	didx = p_write_symbol(literal, strlen(literal) + 1);
	ii = add_instr(op_load_data_address);
	ii->param_no = param_no;
	ii->int_param1 = didx;
}

void p_read_numeric_param(int param_no, int isneg)
{
	char token[MAX_ID_LEN];
	int value = 0;
	int i = 0;
	il_instr *ii;
	char c;

	l_ident(t_numeric, token);

	if (token[0] == '-') {
		isneg = 1 - isneg;
		i++;
	}
	if (token[0] == '0' && (token[1] == 'x' || token[0] == 'X')) {
		i = 2;
		do {
			c = token[i++];
			if (c >= '0' && c <= '9') {
				c -= '0';
			} else if (c >= 'a' && c <= 'f') {
				c -= 'a';
				c += 10;
			} else if (c >= 'A' && c <= 'F') {
				c -= 'A';
				c += 10;
			} else {
				error("Invalid numeric constant");
			}

			value = (value * 16) + c;
		} while (is_hex(token[i]));
	} else {
		do {
			c = token[i++] - '0';
			value = (value * 10) + c;
		} while (is_digit(token[i]));
	}

	ii = add_instr(op_load_numeric_constant);
	ii->param_no = param_no;
	if (isneg) {
		value = -value;
	}
	ii->int_param1 = value;
}

void p_read_char_param(int param_no)
{
	il_instr *ii;
	char token[5];

	l_ident(t_char, token);

	ii = add_instr(op_load_numeric_constant);
	ii->param_no = param_no;
	ii->int_param1 = token[0];
}

void p_read_pointer_call(int param_no, block_def *parent)
{
	il_instr *ii;

	/* preserve existing paremeters */
	int pn;
	for (pn = 0; pn < param_no; pn++) {
		ii = add_instr(op_push);
		ii->param_no = pn;
	}

	/* remember address on stack */
	ii = add_instr(op_push);
	ii->param_no = param_no;

	p_read_function_parameters(parent);

	/* retrieve address from stack into last parameter */
	ii = add_instr(op_pop);
	ii->param_no = MAX_PARAMS - 1;

	ii = add_instr(op_pointer_call);
	ii->int_param1 = MAX_PARAMS - 1; /* register with address */
	ii->param_no = param_no; /* return value here */

	/* restore existing parameters */
	for (pn = param_no - 1; pn >= 0; pn--) {
		ii = add_instr(op_pop);
		ii->param_no = pn;
	}
}

/* maintain a stack of expression values and operators,
 depending on next operators's priority either apply it or operator on stack first */
void p_read_expression_operand(int param_no, block_def *parent)
{
	int isneg = 0;
	if (l_accept(t_minus)) {
		isneg = 1;
		if (l_peek(t_numeric, NULL) == 0 && l_peek(t_identifier, NULL) == 0 &&
		    l_peek(t_op_bracket, NULL) == 0) {
			error("Unexpected token after unary minus");
		}
	}

	if (l_peek(t_string, NULL)) {
		p_read_literal_param(param_no);
	} else if (l_peek(t_char, NULL)) {
		p_read_char_param(param_no);
	} else if (l_peek(t_numeric, NULL)) {
		p_read_numeric_param(param_no, isneg);
	} else if (l_accept(t_log_not)) {
		il_instr *ii;
		p_read_expression_operand(param_no, parent);
		ii = add_instr(op_not);
		ii->param_no = param_no;
	} else if (l_accept(t_ampersand)) {
		char token[MAX_VAR_LEN];
		variable_def *var;
		lvalue_def lvalue;

		l_peek(t_identifier, token);
		var = find_variable(token, parent);
		p_read_lvalue(&lvalue, var, parent, param_no, 0, op_generic);
	} else if (l_peek(t_star, NULL)) {
		/* dereference */
		char token[MAX_VAR_LEN];
		variable_def *var;
		lvalue_def lvalue;
		il_instr *ii;

		l_accept(t_op_bracket);
		l_peek(t_identifier, token);
		var = find_variable(token, parent);
		p_read_lvalue(&lvalue, var, parent, param_no, 1, op_generic);
		l_accept(t_cl_bracket);
		ii = add_instr(op_read_addr);
		ii->param_no = param_no;
		ii->int_param1 = param_no;
		ii->int_param2 = lvalue.size;
	} else if (l_accept(t_op_bracket)) {
		p_read_expression(param_no, parent);
		l_expect(t_cl_bracket);

		if (isneg) {
			il_instr *ii = add_instr(op_negate);
			ii->param_no = param_no;
		}
	} else if (l_accept(t_sizeof)) {
		char token[MAX_TYPE_LEN];
		type_def *type;
		il_instr *ii = add_instr(op_load_numeric_constant);

		l_expect(t_op_bracket);
		l_ident(t_identifier, token);
		type = find_type(token);
		if (type == NULL) {
			error("Unable to find type");
		}

		ii->param_no = param_no;
		ii->int_param1 = type->size;
		l_expect(t_cl_bracket);
	} else {
		/* function call, constant or variable - read token and determine */
		il_op prefix_op = op_generic;
		char token[MAX_ID_LEN];
		function_def *fn;
		variable_def *var;
		constant_def *con;

		if (l_accept(t_plusplus))
			prefix_op = op_add;
		else if (l_accept(t_minusminus))
			prefix_op = op_sub;

		l_peek(t_identifier, token);

		/* is it a constant or variable? */
		con = find_constant(token);
		var = find_variable(token, parent);
		fn = find_function(token);

		if (con != NULL) {
			int value = con->value;
			il_instr *ii = add_instr(op_load_numeric_constant);
			ii->param_no = param_no;
			ii->int_param1 = value;
			l_expect(t_identifier);
		} else if (var != NULL) {
			/* evalue lvalue expression */
			lvalue_def lvalue;
			p_read_lvalue(&lvalue, var, parent, param_no, 1, prefix_op);
			/* is it a function pointer call? */
			if (l_peek(t_op_bracket, NULL)) {
				p_read_pointer_call(param_no, parent);
			}
		} else if (fn != NULL) {
			il_instr *ii;
			int pn;

			for (pn = 0; pn < param_no; pn++) {
				ii = add_instr(op_push);
				ii->param_no = pn;
			}

			/* we should push existing parameters onto the stack since function calls use same? */
			p_read_function_call(fn, param_no, parent);

			for (pn = param_no - 1; pn >= 0; pn--) {
				ii = add_instr(op_pop);
				ii->param_no = pn;
			}
		} else {
			printf("%s\n", token);
			error("Unrecognized expression token"); /* unknown expression */
		}

		if (isneg) {
			il_instr *ii = add_instr(op_negate);
			ii->param_no = param_no;
		}
	}
}

int p_get_operator_priority(il_op op)
{
	if (op == op_log_and || op == op_log_or) {
		return -2; /* apply last, lowest priority */
	}
	if (op == op_equals || op == op_not_equals || op == op_less_than || op == op_less_eq_than ||
	    op == op_greater_than || op == op_greater_eq_than) {
		return -1; /* apply second last, low priority */
	}
	if (op == op_mul) {
		return 1; /* apply first, high priority */
	}
	return 0; /* everything else left to right */
}

il_op p_get_operator()
{
	il_op op = op_generic;
	if (l_accept(t_plus))
		op = op_add;
	else if (l_accept(t_minus))
		op = op_sub;
	else if (l_accept(t_star))
		op = op_mul;
	else if (l_accept(t_lshift))
		op = op_bit_lshift;
	else if (l_accept(t_rshift))
		op = op_bit_rshift;
	else if (l_accept(t_log_and))
		op = op_log_and;
	else if (l_accept(t_log_or))
		op = op_log_or;
	else if (l_accept(t_eq))
		op = op_equals;
	else if (l_accept(t_noteq))
		op = op_not_equals;
	else if (l_accept(t_lt))
		op = op_less_than;
	else if (l_accept(t_le))
		op = op_less_eq_than;
	else if (l_accept(t_gt))
		op = op_greater_than;
	else if (l_accept(t_ge))
		op = op_greater_eq_than;
	else if (l_accept(t_ampersand))
		op = op_bit_and;
	else if (l_accept(t_bit_or))
		op = op_bit_or;
	return op;
}

void p_read_expression(int param_no, block_def *parent)
{
	il_op op_stack[10];
	int op_stack_idx = 0;
	il_op op, next_op;
	il_instr *il;

	/* read value into param_no */
	p_read_expression_operand(param_no, parent);

	/* check for any operator following */
	op = p_get_operator();
	if (op == op_generic)
		/* no continuation */
		return;

	p_read_expression_operand(param_no + 1, parent);
	next_op = p_get_operator();

	if (next_op == op_generic) {
		/* only two operands, apply and return */
		il = add_instr(op);
		il->param_no = param_no;
		il->int_param1 = param_no + 1;
		return;
	}

	/* more than two operands - use stack */
	il = add_instr(op_push);
	il->param_no = param_no;
	il = add_instr(op_push);
	il->param_no = param_no + 1;
	op_stack[0] = op;
	op_stack_idx++;
	op = next_op;

	while (op != op_generic) {
		/* we have a continuation, use stack */
		int same_op = 0;

		/* if we have operand on stack, compare priorities */
		if (op_stack_idx > 0) {
			do {
				il_op stack_op = op_stack[op_stack_idx - 1];
				if (p_get_operator_priority(stack_op) >= p_get_operator_priority(op)) {
					/* stack has higher priority operator i.e. 5 * 6 + _ */
					/* pop stack and apply operators */
					il = add_instr(op_pop);
					il->param_no = param_no + 1;

					il = add_instr(op_pop);
					il->param_no = param_no;

					/* apply stack operator  */
					il = add_instr(stack_op);
					il->param_no = param_no;
					il->int_param1 = param_no + 1;

					/* push value back on stack */
					il = add_instr(op_push);
					il->param_no = param_no;

					/* pop op stack */
					op_stack_idx--;
				} else {
					same_op = 1;
				}
				/* continue util next operation is higher priority, i.e. 5 + 6 * _ */
			} while (op_stack_idx > 0 && same_op == 0);
		}

		/* push operator on stack */
		op_stack[op_stack_idx++] = op;

		/* push value on stack */
		p_read_expression_operand(param_no, parent);
		il = add_instr(op_push);
		il->param_no = param_no;

		op = p_get_operator();
	}

	/* unwind stack and apply operations */
	while (op_stack_idx > 0) {
		il_op stack_op = op_stack[op_stack_idx - 1];

		/* pop stack and apply operators */
		il = add_instr(op_pop);
		il->param_no = param_no + 1;

		il = add_instr(op_pop);
		il->param_no = param_no;

		/* apply stack operator  */
		il = add_instr(stack_op);
		il->param_no = param_no;
		il->int_param1 = param_no + 1;

		if (op_stack_idx == 1) {
			/* done */
			return;
		}

		/* push value back on stack */
		il = add_instr(op_push);
		il->param_no = param_no;

		/* pop op stack */
		op_stack_idx--;
	}

	error("Unexpected end of expression");
}

void p_read_function_parameters(block_def *parent)
{
	int param_num = 0;
	l_expect(t_op_bracket);
	while (!l_accept(t_cl_bracket)) {
		p_read_expression(param_num++, parent);
		l_accept(t_comma);
	}
}

void p_read_function_call(function_def *fn, int param_no, block_def *parent)
{
	il_instr *ii;

	/* we already have function name in fn */
	l_expect(t_identifier);
	if (l_peek(t_op_bracket, NULL)) {
		/* function call */
		p_read_function_parameters(parent);
		ii = add_instr(op_function_call);
		ii->string_param1 = fn->return_def.variable_name;
		ii->param_no = param_no; /* return value here */
	} else {
		/* function pointer */
		ii = add_instr(op_get_var_addr);
		ii->string_param1 = fn->return_def.variable_name;
		ii->param_no = param_no; /* return value here */
	}
}

/* returns address an expression points to, or evaluates its value */
/* x =; x[<expr>] =; x[expr].field =; x[expr]->field =; x + ... */
void p_read_lvalue(lvalue_def *lvalue, variable_def *var, block_def *parent, int param_no, int evaluate,
		   il_op prefix_op)
{
	il_instr *ii;
	int is_reference = 1;

	l_expect(t_identifier); /* we've already peeked and have the variable */

	/* load memory location into param */
	ii = add_instr(op_get_var_addr);
	ii->param_no = param_no;
	ii->string_param1 = var->variable_name;
	lvalue->type = find_type(var->type_name);
	lvalue->size = p_get_size(var, lvalue->type);
	lvalue->is_pointer = var->is_pointer;
	if (var->array_size > 0) {
		is_reference = 0;
	}

	while (l_peek(t_op_square, NULL) || l_peek(t_arrow, NULL) || l_peek(t_dot, NULL)) {
		if (l_accept(t_op_square)) {
			is_reference = 1;
			if (var->is_pointer <= 1) {
				/* if nested pointer, still pointer */
				lvalue->size = lvalue->type->size;
			}

			/* offset, so var must be either a pointer or an array of some type */
			if (var->is_pointer == 0 && var->array_size == 0)
				error("Cannot apply square operator to non-pointer");

			/* if var is an array, the memory location points to its start,
				but if var is a pointer, we need to dereference */
			if (var->is_pointer) {
				ii = add_instr(op_read_addr);
				ii->param_no = param_no;
				ii->int_param1 = param_no;
				ii->int_param2 = PTR_SIZE; /* pointer */
			}

			p_read_expression(param_no + 1, parent); /* param+1 has the offset in array terms */

			/* multiply by element size */
			if (lvalue->size != 1) {
				ii = add_instr(op_load_numeric_constant);
				ii->int_param1 = lvalue->size;
				ii->param_no = param_no + 2;

				ii = add_instr(op_mul);
				ii->param_no = param_no + 1;
				ii->int_param1 = param_no + 2;
			}

			ii = add_instr(op_add);
			ii->param_no = param_no;
			ii->int_param1 = param_no + 1;

			l_expect(t_cl_square);
		} else {
			char token[MAX_ID_LEN];

			if (l_accept(t_arrow)) {
				/* dereference first */
				ii = add_instr(op_read_addr);
				ii->param_no = param_no;
				ii->int_param1 = param_no;
				ii->int_param2 = PTR_SIZE;
			} else {
				l_expect(t_dot);
			}

			l_ident(t_identifier, token);

			/* change type currently pointed to */
			var = find_member(token, lvalue->type);
			lvalue->type = find_type(var->type_name);
			lvalue->is_pointer = var->is_pointer;

			/* reset target */
			is_reference = 1;
			lvalue->size = p_get_size(var, lvalue->type);
			if (var->array_size > 0) {
				is_reference = 0;
			}

			/* move pointer to offset of structure */
			ii = add_instr(op_load_numeric_constant);
			ii->int_param1 = var->offset;
			ii->param_no = param_no + 1;

			ii = add_instr(op_add);
			ii->param_no = param_no;
			ii->int_param1 = param_no + 1;
		}
	}

	if (evaluate) {
		/* do we need to apply pointer arithmetic? */
		if (l_peek(t_plus, NULL) && (var->is_pointer > 0 || var->array_size > 0)) {
			l_accept(t_plus);

			/* dereference if necessary */
			if (is_reference) {
				ii = add_instr(op_read_addr);
				ii->param_no = param_no;
				ii->int_param1 = param_no;
				ii->int_param2 = PTR_SIZE;
			}

			p_read_expression_operand(param_no + 1, parent); /* param+1 has the offset in array terms */

			/* shift by offset in type sizes */
			lvalue->size = lvalue->type->size;

			/* multiply by element size */
			if (lvalue->size != 1) {
				ii = add_instr(op_load_numeric_constant);
				ii->int_param1 = lvalue->size;
				ii->param_no = param_no + 2;

				ii = add_instr(op_mul);
				ii->param_no = param_no + 1;
				ii->int_param1 = param_no + 2;
			}

			ii = add_instr(op_add);
			ii->param_no = param_no;
			ii->int_param1 = param_no + 1;
		} else {
			/* we should NOT dereference if var is of type array and there was no offset */
			if (is_reference) {
				if (prefix_op != op_generic) {
					/* read into p+1 */
					ii = add_instr(op_read_addr);
					ii->param_no = param_no + 1;
					ii->int_param1 = param_no;
					ii->int_param2 = lvalue->size;

					/* load 1 */
					ii = add_instr(op_load_numeric_constant);
					ii->param_no = param_no + 2;
					ii->int_param1 = 1;

					/* add/sub */
					ii = add_instr(prefix_op);
					ii->param_no = param_no + 1;
					ii->int_param1 = param_no + 2;

					/* store */
					ii = add_instr(op_write_addr);
					ii->param_no = param_no + 1;
					ii->int_param1 = param_no;
					ii->int_param2 = lvalue->size;
				}
				if (l_peek(t_plusplus, NULL) || l_peek(t_minusminus, NULL)) {
					/* load value into param_no + 1 */
					ii = add_instr(op_read_addr);
					ii->param_no = param_no + 1;
					ii->int_param1 = param_no;
					ii->int_param2 = lvalue->size;

					/* push the value */
					ii = add_instr(op_push);
					ii->param_no = param_no + 1;

					/* load 1 */
					ii = add_instr(op_load_numeric_constant);
					ii->param_no = param_no + 2;
					ii->int_param1 = 1;

					/* add 1 */
					if (l_accept(t_plusplus))
						ii = add_instr(op_add);
					else
						ii = add_instr(op_sub);
					ii->param_no = param_no + 1;
					ii->int_param1 = param_no + 2;

					/* store */
					ii = add_instr(op_write_addr);
					ii->param_no = param_no + 1;
					ii->int_param1 = param_no;
					ii->int_param2 = lvalue->size;

					/* pop original  value */
					ii = add_instr(op_pop);
					ii->param_no = param_no;
				} else {
					ii = add_instr(op_read_addr);
					ii->param_no = param_no;
					ii->int_param1 = param_no;
					ii->int_param2 = lvalue->size;
				}
			}
		}
	}
}

int p_read_body_assignment(char *token, block_def *parent)
{
	il_instr *ii;
	variable_def *var = find_local_variable(token, parent);
	if (var == NULL)
		var = find_global_variable(token);
	if (var != NULL) {
		int one = 0;
		il_op op = op_generic;
		lvalue_def lvalue;
		int size = 0;

		/* a0 has memory address we want to set */
		p_read_lvalue(&lvalue, var, parent, 0, 0, op_generic);
		size = lvalue.size;

		if (l_accept(t_plusplus)) {
			op = op_add;
			one = 1;
		} else if (l_accept(t_minusminus)) {
			op = op_sub;
			one = 1;
		} else if (l_accept(t_pluseq)) {
			op = op_add;
		} else if (l_accept(t_minuseq)) {
			op = op_sub;
		} else if (l_accept(t_oreq)) {
			op = op_bit_or;
		} else if (l_accept(t_andeq)) {
			op = op_bit_and;
		} else if (l_peek(t_op_bracket, NULL)) {
			/* dereference lvalue into function address */
			ii = add_instr(op_read_addr);
			ii->param_no = 0;
			ii->int_param1 = 0;
			ii->int_param2 = lvalue.size;
			p_read_pointer_call(0, parent);
			return 1;
		} else {
			l_expect(t_assign);
		}

		if (op != op_generic) {
			int increment_size = 1;

			/* if we have a pointer, we shift it by element size */
			if (lvalue.is_pointer)
				increment_size = lvalue.type->size;

			/* get current value into a1 */
			ii = add_instr(op_read_addr);
			ii->param_no = 1;
			ii->int_param1 = 0;
			ii->int_param2 = size;

			/* set a2 with either 1 or expression value */
			if (one == 1) {
				ii = add_instr(op_load_numeric_constant);
				ii->param_no = 2;
				ii->int_param1 = increment_size;
			} else {
				p_read_expression(2, parent);

				/* multiply by element size if necessary */
				if (increment_size != 1) {
					ii = add_instr(op_load_numeric_constant);
					ii->param_no = 3;
					ii->int_param1 = increment_size;

					ii = add_instr(op_mul);
					ii->param_no = 2;
					ii->int_param1 = 3;
				}
			}

			/* apply operation to value in a1 */
			ii = add_instr(op);
			ii->param_no = 1;
			ii->int_param1 = 2;
		} else {
			p_read_expression(1, parent); /* get expression value into a1 */
		}

		/* store a1 at addr a0, but need to know the type/size */
		ii = add_instr(op_write_addr);
		ii->param_no = 1;
		ii->int_param1 = 0;
		ii->int_param2 = size;

		return 1;
	}
	return 0;
}

void p_read_body_statement(block_def *parent)
{
	char token[MAX_ID_LEN];
	function_def *fn;
	type_def *type;
	variable_def *var;
	il_instr *ii;

	/* statement can be: function call, variable declaration, assignment operation, keyword, block */

	if (l_peek(t_op_curly, NULL)) {
		p_read_code_block(parent->function, parent);
		return;
	}

	if (l_accept(t_return)) {
		if (!l_accept(t_semicolon)) /* can be void */
		{
			p_read_expression(0, parent); /* get expression value into a0 / return value */
			l_expect(t_semicolon);
		}
		fn = parent->function;
		ii = add_instr(op_return);
		ii->string_param1 = fn->return_def.variable_name;
		return;
	}

	if (l_accept(t_if)) {
		il_instr *false_jump;
		il_instr *true_jump;

		l_expect(t_op_bracket);
		p_read_expression(0, parent); /* get expression value into a0 / return value */
		l_expect(t_cl_bracket);

		false_jump = add_instr(op_jz);
		false_jump->param_no = 0;

		p_read_body_statement(parent);

		/* if we have an else block, jump to finish */
		if (l_accept(t_else)) {
			/* jump true branch to finish */
			true_jump = add_instr(op_jump);

			/* we will emit false branch, link false jump here */
			ii = add_instr(op_label);
			false_jump->int_param1 = ii->il_index;

			/* false branch */
			p_read_body_statement(parent);

			/* this is finish, link true jump */
			ii = add_instr(op_label);
			true_jump->int_param1 = ii->il_index;
		} else {
			/* this is finish, link false jump */
			ii = add_instr(op_label);
			false_jump->int_param1 = ii->il_index;
		}
		return;
	}

	if (l_accept(t_while)) {
		il_instr *false_jump;
		il_instr *start;

		start = add_instr(op_label); /* start to return to */

		l_expect(t_op_bracket);
		p_read_expression(0, parent); /* get expression value into a0 / return value */
		l_expect(t_cl_bracket);

		false_jump = add_instr(op_jz);
		false_jump->param_no = 0;

		p_read_body_statement(parent);

		/* unconditional jump back to expression */
		ii = add_instr(op_jump);
		ii->int_param1 = start->il_index;

		/* exit label */
		ii = add_instr(op_label);
		false_jump->int_param1 = ii->il_index;
		return;
	}

	if (l_accept(t_switch)) {
		int case_values[MAX_CASES];
		int case_il_idxs[MAX_CASES];
		int case_idx = 0;
		int default_il_idx = 0;
		int i;
		il_instr *jump_to_check;
		il_instr *switch_exit;

		l_expect(t_op_bracket);
		p_read_expression(1, parent);
		l_expect(t_cl_bracket);

		jump_to_check = add_instr(op_jump);

		/* create exit jump for breaks */
		switch_exit = add_instr(op_jump);
		_p_break_exit_il_idxs[_p_break_level++] = switch_exit->il_index;

		l_expect(t_op_curly);
		while (l_peek(t_default, NULL) || l_peek(t_case, NULL)) {
			if (l_accept(t_default)) {
				ii = add_instr(op_label);
				default_il_idx = ii->il_index;
			} else {
				int case_val;

				l_accept(t_case);
				if (l_peek(t_numeric, NULL)) {
					case_val = p_read_numeric_constant(_l_token_string);
					l_expect(t_numeric); /* already read it */
				} else {
					constant_def *cd = find_constant(_l_token_string);
					case_val = cd->value;
					l_expect(t_identifier); /* already read it */
				}
				ii = add_instr(op_label);
				case_values[case_idx] = case_val;
				case_il_idxs[case_idx++] = ii->il_index;
			}
			l_expect(t_colon);

			/* body is optional, can be another case */
			while (!l_peek(t_case, NULL) && !l_peek(t_cl_curly, NULL) && !l_peek(t_default, NULL)) {
				p_read_body_statement(parent);
				/* should end with a break which will generate jump out */
			}
		}
		l_expect(t_cl_curly);

		ii = add_instr(op_label);
		jump_to_check->int_param1 = ii->il_index;

		/* perform checks against a1 */
		for (i = 0; i < case_idx; i++) {
			ii = add_instr(op_load_numeric_constant);
			ii->param_no = 0;
			ii->int_param1 = case_values[i];
			ii = add_instr(op_equals);
			ii->param_no = 0;
			ii->int_param1 = 1;
			ii = add_instr(op_jnz);
			ii->param_no = 0;
			ii->int_param1 = case_il_idxs[i];
		}
		/* jump to default */
		if (default_il_idx != 0) {
			ii = add_instr(op_jump);
			ii->int_param1 = default_il_idx;
		}

		_p_break_level--;

		/* exit where breaks should exit to */
		ii = add_instr(op_label);
		switch_exit->int_param1 = ii->il_index;

		return;
	}

	if (l_accept(t_break)) {
		ii = add_instr(op_jump);
		ii->int_param1 = _p_break_exit_il_idxs[_p_break_level - 1];
	}

	if (l_accept(t_for)) {
		char token[MAX_VAR_LEN];
		il_instr *condition_start;
		il_instr *condition_jump_out;
		il_instr *condition_jump_in;
		il_instr *increment;
		il_instr *increment_jump;
		il_instr *body_start;
		il_instr *body_jump;
		il_instr *end;

		l_expect(t_op_bracket);

		/* setup - execute once */
		if (!l_accept(t_semicolon)) {
			l_peek(t_identifier, token);
			p_read_body_assignment(token, parent);
			l_expect(t_semicolon);
		}

		/* condition - check before the loop */
		condition_start = add_instr(op_label);
		if (!l_accept(t_semicolon)) {
			p_read_expression(0, parent);
			l_expect(t_semicolon);
		} else {
			/* always true */
			il_instr *true = add_instr(op_load_numeric_constant);
			true->param_no = 0;
			true->int_param1 = 1;
		}

		condition_jump_out = add_instr(op_jz); /* jump out if zero */
		condition_jump_out->param_no = 0;
		condition_jump_in = add_instr(op_jump); /* else jump to body */
		condition_jump_in->param_no = 0;

		/* increment after each loop */
		increment = add_instr(op_label);
		if (!l_accept(t_cl_bracket)) {
			l_peek(t_identifier, token);
			p_read_body_assignment(token, parent);
			l_expect(t_cl_bracket);
		}

		/* jump back to condition */
		increment_jump = add_instr(op_jump);
		increment_jump->int_param1 = condition_start->il_index;

		/* loop body */
		body_start = add_instr(op_label);
		condition_jump_in->int_param1 = body_start->il_index;
		p_read_body_statement(parent);

		/* jump to increment */
		body_jump = add_instr(op_jump);
		body_jump->int_param1 = increment->il_index;

		end = add_instr(op_label);
		condition_jump_out->int_param1 = end->il_index;
		return;
	}

	if (l_accept(t_do)) {
		il_instr *false_jump;
		il_instr *start;

		start = add_instr(op_label); /* start to return to */

		p_read_body_statement(parent);
		l_expect(t_while);
		l_expect(t_op_bracket);
		p_read_expression(0, parent); /* get expression value into a0 / return value */
		l_expect(t_cl_bracket);

		false_jump = add_instr(op_jnz);
		false_jump->param_no = 0;
		false_jump->int_param1 = start->il_index;

		l_expect(t_semicolon);
		return;
	}

	if (l_accept(t_asm)) {
		char value[MAX_ID_LEN];
		int val;

		l_expect(t_op_bracket);
		l_ident(t_numeric, value);
		val = p_read_numeric_constant(value);
		l_expect(t_cl_bracket);
		l_expect(t_semicolon);

		add_generic(val);
		return;
	}

	if (l_accept(t_semicolon)) {
		/* empty statement */
		return;
	}

	/* must be an identifier */
	if (!l_peek(t_identifier, token)) {
		error("Unexpected token");
	}

	/* is it a variable declaration? */
	type = find_type(token);
	if (type != NULL) {
		var = &parent->locals[parent->next_local++];
		p_read_full_variable_declaration(var, 0);
		if (l_accept(t_assign)) {
			p_read_expression(1, parent); /* get expression value into a1 */
			/* assign a0 to our new variable */

			/* load variable location into a0 */
			ii = add_instr(op_get_var_addr);
			ii->param_no = 0;
			ii->string_param1 = var->variable_name;

			/* store a1 at addr a0, but need to know the type/size */
			ii = add_instr(op_write_addr);
			ii->param_no = 1;
			ii->int_param1 = 0;
			ii->int_param2 = p_get_size(var, type);
		}
		while (l_accept(t_comma)) {
			/* multiple (partial) declarations */
			variable_def *nv;

			nv = &parent->locals[parent->next_local++];
			p_read_partial_variable_declaration(nv, var); /* partial */
			if (l_accept(t_assign)) {
				p_read_expression(1, parent); /* get expression value into a1 */
				/* assign a0 to our new variable */

				/* load variable location into a0 */
				ii = add_instr(op_get_var_addr);
				ii->param_no = 0;
				ii->string_param1 = nv->variable_name;

				/* store a1 at addr a0, but need to know the type/size */
				ii = add_instr(op_write_addr);
				ii->param_no = 1;
				ii->int_param1 = 0;
				ii->int_param2 = p_get_size(var, type);
			}
		}
		l_expect(t_semicolon);
		return;
	}

	/* is it a function call? */
	fn = find_function(token);
	if (fn != NULL) {
		p_read_function_call(fn, 0, parent);
		l_expect(t_semicolon);
		return;
	}

	/* is it an assignment? */
	if (p_read_body_assignment(token, parent)) {
		l_expect(t_semicolon);
		return;
	}

	error("Unrecognized statement token");
}

void p_read_code_block(function_def *function, block_def *parent)
{
	block_def *bd;
	il_instr *ii;

	bd = add_block(parent, function);
	ii = add_instr(op_block_start);
	ii->int_param1 = bd->bd_index;
	l_expect(t_op_curly);

	while (!l_accept(t_cl_curly))
		p_read_body_statement(bd);

	ii = add_instr(op_block_end);
	ii->int_param1 = bd->bd_index;
}

void p_read_function_body(function_def *fdef)
{
	il_instr *ii;

	p_read_code_block(fdef, NULL);

	/* only add return when we have no return type, as otherwise there should have been a return statement */
	ii = add_instr(op_exit_point);
	ii->string_param1 = fdef->return_def.variable_name;
	fdef->exit_point = ii->il_index;
}

/* if first token in is type */
void p_read_global_declaration(block_def *block)
{
	/* new function, or variables under parent */
	p_read_full_variable_declaration(_temp_variable, 0);

	if (l_peek(t_op_bracket, NULL)) {
		function_def *fd;
		il_instr *ii;

		/* function */
		fd = add_function(_temp_variable->variable_name);
		memcpy(&fd->return_def, _temp_variable, sizeof(variable_def));

		fd->num_params = p_read_parameter_list_declaration(fd->param_defs, 0);

		if (l_peek(t_op_curly, NULL)) {
			ii = add_instr(op_entry_point);
			ii->string_param1 = fd->return_def.variable_name;
			fd->entry_point = ii->il_index;

			p_read_function_body(fd);
			return;
		} else if (l_accept(t_semicolon)) {
			/* forward definition */
			return;
		}
		error("Syntax error in global declaration");
	}

	/* it's a variable */
	memcpy(&block->locals[block->next_local++], _temp_variable, sizeof(variable_def));

	if (l_accept(t_assign))
		/* we don't support global initialisation */
		error("Global initialization not supported");
	else if (l_accept(t_comma))
		/* TODO: continuation */
		error("Global continuation not supported");
	else if (l_accept(t_semicolon))
		return;
	error("Syntax error in global declaration");
}

void p_read_global_statement()
{
	char token[MAX_ID_LEN];
	block_def *block;

	block = &_blocks[0]; /* global block */

	if (l_peek(t_include, token)) {
		if (strcmp(_l_token_string, "<stdio.h>") == 0) {
			/* ignore, we inclue rvclib by default */
		}
		l_expect(t_include);
	} else if (l_accept(t_define)) {
		char alias[MAX_VAR_LEN];
		char value[MAX_VAR_LEN];

		l_peek(t_identifier, alias);
		l_expect(t_identifier);
		l_peek(t_numeric, value);
		l_expect(t_numeric);
		add_alias(alias, value);
	} else if (l_accept(t_typedef)) {
		if (l_accept(t_enum)) {
			int val = 0;
			char token[MAX_TYPE_LEN];
			type_def *type = add_type();

			type->base_type = bt_int;
			type->size = 4;
			l_expect(t_op_curly);
			do {
				l_ident(t_identifier, token);
				if (l_accept(t_assign)) {
					char value[MAX_ID_LEN];
					l_ident(t_numeric, value);
					val = p_read_numeric_constant(value);
				}
				add_constant(token, val++);
			} while (l_accept(t_comma));
			l_expect(t_cl_curly);
			l_ident(t_identifier, token);
			strcpy(type->type_name, token);
			l_expect(t_semicolon);
		} else if (l_accept(t_struct)) {
			char token[MAX_TYPE_LEN];
			int i = 0, size = 0;
			type_def *type = add_type();

			if (l_peek(t_identifier, token)) {
				/* for recursive declaration */
				l_accept(t_identifier);
			}
			l_expect(t_op_curly);
			do {
				variable_def *v = &type->fields[i++];
				p_read_full_variable_declaration(v, 0);
				v->offset = size;
				size += size_variable(v);
				l_expect(t_semicolon);
			} while (!l_accept(t_cl_curly));

			l_ident(t_identifier, token); /* type name */
			strcpy(type->type_name, token);
			type->size = size;
			type->num_fields = i;
			type->base_type = bt_struct; /* is this used? */
			l_expect(t_semicolon);
		} else {
			char base_type[MAX_TYPE_LEN];
			type_def *base;
			type_def *type = add_type();
			l_ident(t_identifier, base_type);
			base = find_type(base_type);
			if (base == NULL) {
				error("Unable to find base type");
			}
			type->base_type = base->base_type;
			type->size = base->size;
			type->num_fields = 0;
			l_ident(t_identifier, type->type_name);
			l_expect(t_semicolon);
		}
	} else if (l_peek(t_identifier, NULL)) {
		p_read_global_declaration(block);
	} else {
		error("Syntax error in global statement");
	}
}

void p_parse()
{
	p_initialize();
	l_initialize();
	do {
		p_read_global_statement();
	} while (!l_accept(t_eof));
}

/* rvcc C compiler - RISC-V ISA encoder */

/* RISC-V opcodes */
typedef enum {
	/* R type */
	ri_add = 51 /* 0b110011 + (0 << 12) */,
	ri_sub = 1073741875 /* 0b110011 + (0 << 12) + (0x20 << 25) */,
	ri_xor = 16435 /* 0b110011 + (4 << 12) */,
	ri_or = 24627 /* 0b110011 + (6 << 12) */,
	ri_and = 28723 /* 0b110011 + (7 << 12) */,
	ri_sll = 4147 /* 0b110011 + (1 << 12) */,
	ri_srl = 20531 /* 0b110011 + (5 << 12) */,
	ri_sra = 1073762355 /* 0b110011 + (5 << 12) + (0x20 << 25) */,
	ri_slt = 8243 /* 0b110011 + (2 << 12) */,
	ri_sltu = 12339 /* 0b110011 + (3 << 12) */,
	/* I type */
	ri_addi = 19 /* 0b0010011 */,
	ri_xori = 16403 /* 0b0010011 + (4 << 12) */,
	ri_ori = 24595 /* 0b0010011 + (6 << 12) */,
	ri_andi = 28691 /* 0b0010011 + (7 << 12) */,
	ri_slli = 4115 /* 0b0010011 + (1 << 12) */,
	ri_srli = 20499 /* 0b0010011 + (5 << 12) */,
	ri_srai = 1073762323 /* 0b0010011 + (5 << 12) + (0x20 << 25) */,
	ri_slti = 8211 /* 0b0010011 + (2 << 12) */,
	ri_sltiu = 12307 /* 0b0010011 + (3 << 12) */,
	/* load/store */
	ri_lb = 3 /* 0b11 */,
	ri_lh = 4099 /* 0b11 + (1 << 12) */,
	ri_lw = 8195 /* 0b11 + (2 << 12) */,
	ri_lbu = 16387 /* 0b11 + (4 << 12) */,
	ri_lhu = 20483 /* 0b11 + (5 << 12) */,
	ri_sb = 35 /* 0b0100011 */,
	ri_sh = 4131 /* 0b0100011 + (1 << 12) */,
	ri_sw = 8227 /* 0b0100011 + (2 << 12) */,
	/* branch */
	ri_beq = 99 /* 0b1100011 */,
	ri_bne = 4195 /* 0b1100011 + (1 << 12) */,
	ri_blt = 16483 /* 0b1100011 + (4 << 12) */,
	ri_bge = 20579 /* 0b1100011 + (5 << 12) */,
	ri_bltu = 24675 /* 0b1100011 + (6 << 12) */,
	ri_bgeu = 28771 /* 0b1100011 + (7 << 12) */,
	/* jumps */
	ri_jal = 111 /* 0b1101111 */,
	ri_jalr = 103 /* 0b1100111 */,
	/* misc */
	ri_lui = 55 /* 0b0110111 */,
	ri_auipc = 23 /*0 b0010111 */,
	ri_ecall = 115 /* 0b1110011 */,
	ri_ebreak = 1048691 /* 0b1110011 + (1 << 20) */,
	/* m */
	ri_mul = 33554483 /* 0b0110011 + (1 << 25) */
} ri_op;

/* RISC-V registers */
typedef enum {
	r_zero = 0,
	r_ra = 1,
	r_sp = 2,
	r_gp = 3,
	r_tp = 4,
	r_t0 = 5,
	r_t1 = 6,
	r_t2 = 7,
	r_s0 = 8,
	r_s1 = 9,
	r_a0 = 10,
	r_a1 = 11,
	r_a2 = 12,
	r_a3 = 13,
	r_a4 = 14,
	r_a5 = 15,
	r_a6 = 16,
	r_a7 = 17,
	r_s2 = 18,
	r_s3 = 19,
	r_s4 = 20,
	r_s5 = 21,
	r_s6 = 22,
	r_s7 = 23,
	r_s8 = 24,
	r_s9 = 25,
	r_s10 = 26,
	r_s11 = 27,
	r_t3 = 28,
	r_t4 = 29,
	r_t5 = 30,
	r_t6 = 31
} r_reg;

int r_extract_bits(int imm, int i_start, int i_end, int d_start, int d_end)
{
	int v;

	if (d_end - d_start != i_end - i_start || i_start > i_end || d_start > d_end)
		error("Invalid bit copy");

	v = imm >> i_start;
	v = v & ((2 << (i_end - i_start)) - 1);
	v = v << d_start;
	return v;
}

int r_hi(int val)
{
	if ((val & (1 << 11)) != 0)
		return val + 4096;
	else
		return val;
}

int r_lo(int val)
{
	if ((val & (1 << 11)) != 0)
		return (val & 0xFFF) - 4096;
	else
		return val & 0xFFF;
}

int r_encode_R(ri_op op, r_reg rd, r_reg rs1, r_reg rs2)
{
	return op + (rd << 7) + (rs1 << 15) + (rs2 << 20);
}

int r_encode_I(ri_op op, r_reg rd, r_reg rs1, int imm)
{
	if (imm > 2047 || imm < -2048)
		error("Offset too large");

	if (imm < 0) {
		imm += 4096;
		imm &= (1 << 13) - 1;
	}
	return op + (rd << 7) + (rs1 << 15) + (imm << 20);
}

int r_encode_S(ri_op op, r_reg rs1, r_reg rs2, int imm)
{
	if (imm > 2047 || imm < -2048)
		error("Offset too large");

	if (imm < 0) {
		imm += 4096;
		imm &= (1 << 13) - 1;
	}
	return op + (rs1 << 15) + (rs2 << 20) + r_extract_bits(imm, 0, 4, 7, 11) + r_extract_bits(imm, 5, 11, 25, 31);
}

int r_encode_B(ri_op op, r_reg rs1, r_reg rs2, int imm)
{
	int sign = 0;

	/* 13 signed bits, with bit zero ignored */
	if (imm > 4095 || imm < -4096)
		error("Offset too large");

	if (imm < 0)
		sign = 1;

	return op + (rs1 << 15) + (rs2 << 20) + r_extract_bits(imm, 11, 11, 7, 7) + r_extract_bits(imm, 1, 4, 8, 11) +
	       r_extract_bits(imm, 5, 10, 25, 30) + (sign << 31);
}

int r_encode_J(ri_op op, r_reg rd, int imm)
{
	int sign = 0;

	if (imm < 0) {
		sign = 1;
		imm = -imm;
		imm = (1 << 21) - imm;
	}
	return op + (rd << 7) + r_extract_bits(imm, 1, 10, 21, 30) + r_extract_bits(imm, 11, 11, 20, 20) +
	       r_extract_bits(imm, 12, 19, 12, 19) + (sign << 31);
}

int r_encode_U(ri_op op, r_reg rd, int imm)
{
	return op + (rd << 7) + r_extract_bits(imm, 12, 31, 12, 31);
}

int r_add(r_reg rd, r_reg rs1, r_reg rs2)
{
	return r_encode_R(ri_add, rd, rs1, rs2);
}

int r_sub(r_reg rd, r_reg rs1, r_reg rs2)
{
	return r_encode_R(ri_sub, rd, rs1, rs2);
}

int r_xor(r_reg rd, r_reg rs1, r_reg rs2)
{
	return r_encode_R(ri_xor, rd, rs1, rs2);
}

int r_or(r_reg rd, r_reg rs1, r_reg rs2)
{
	return r_encode_R(ri_or, rd, rs1, rs2);
}

int r_and(r_reg rd, r_reg rs1, r_reg rs2)
{
	return r_encode_R(ri_and, rd, rs1, rs2);
}

int r_sll(r_reg rd, r_reg rs1, r_reg rs2)
{
	return r_encode_R(ri_sll, rd, rs1, rs2);
}

int r_srl(r_reg rd, r_reg rs1, r_reg rs2)
{
	return r_encode_R(ri_srl, rd, rs1, rs2);
}

int r_sra(r_reg rd, r_reg rs1, r_reg rs2)
{
	return r_encode_R(ri_sra, rd, rs1, rs2);
}

int r_slt(r_reg rd, r_reg rs1, r_reg rs2)
{
	return r_encode_R(ri_slt, rd, rs1, rs2);
}

int r_sltu(r_reg rd, r_reg rs1, r_reg rs2)
{
	return r_encode_R(ri_sltu, rd, rs1, rs2);
}

int r_addi(r_reg rd, r_reg rs1, int imm)
{
	return r_encode_I(ri_addi, rd, rs1, imm);
}

int r_xori(r_reg rd, r_reg rs1, int imm)
{
	return r_encode_I(ri_xori, rd, rs1, imm);
}

int r_ori(r_reg rd, r_reg rs1, int imm)
{
	return r_encode_I(ri_ori, rd, rs1, imm);
}

int r_andi(r_reg rd, r_reg rs1, int imm)
{
	return r_encode_I(ri_andi, rd, rs1, imm);
}

int r_slli(r_reg rd, r_reg rs1, int imm)
{
	return r_encode_I(ri_slli, rd, rs1, imm);
}

int r_srli(r_reg rd, r_reg rs1, int imm)
{
	return r_encode_I(ri_srli, rd, rs1, imm);
}

int r_srai(r_reg rd, r_reg rs1, int imm)
{
	return r_encode_I(ri_srai, rd, rs1, imm);
}

int r_slti(r_reg rd, r_reg rs1, int imm)
{
	return r_encode_I(ri_slti, rd, rs1, imm);
}

int r_sltiu(r_reg rd, r_reg rs1, int imm)
{
	return r_encode_I(ri_sltiu, rd, rs1, imm);
}

int r_lb(r_reg rd, r_reg rs1, int imm)
{
	return r_encode_I(ri_lb, rd, rs1, imm);
}

int r_lh(r_reg rd, r_reg rs1, int imm)
{
	return r_encode_I(ri_lh, rd, rs1, imm);
}

int r_lw(r_reg rd, r_reg rs1, int imm)
{
	return r_encode_I(ri_lw, rd, rs1, imm);
}

int r_lbu(r_reg rd, r_reg rs1, int imm)
{
	return r_encode_I(ri_lbu, rd, rs1, imm);
}

int r_lhu(r_reg rd, r_reg rs1, int imm)
{
	return r_encode_I(ri_lhu, rd, rs1, imm);
}

int r_sb(r_reg rd, r_reg rs1, int imm)
{
	return r_encode_S(ri_sb, rs1, rd, imm);
}

int r_sh(r_reg rd, r_reg rs1, int imm)
{
	return r_encode_S(ri_sh, rs1, rd, imm);
}

int r_sw(r_reg rd, r_reg rs1, int imm)
{
	return r_encode_S(ri_sw, rs1, rd, imm);
}

int r_beq(r_reg rs1, r_reg rs2, int imm)
{
	return r_encode_B(ri_beq, rs1, rs2, imm);
}

int r_bne(r_reg rs1, r_reg rs2, int imm)
{
	return r_encode_B(ri_bne, rs1, rs2, imm);
}

int r_blt(r_reg rs1, r_reg rs2, int imm)
{
	return r_encode_B(ri_blt, rs1, rs2, imm);
}

int r_bge(r_reg rs1, r_reg rs2, int imm)
{
	return r_encode_B(ri_bge, rs1, rs2, imm);
}

int r_bltu(r_reg rs1, r_reg rs2, int imm)
{
	return r_encode_B(ri_bltu, rs1, rs2, imm);
}

int r_bgeu(r_reg rs1, r_reg rs2, int imm)
{
	return r_encode_B(ri_bgeu, rs1, rs2, imm);
}

int r_jal(r_reg rd, int imm)
{
	return r_encode_J(ri_jal, rd, imm);
}

int r_jalr(r_reg rd, r_reg rs1, int imm)
{
	return r_encode_I(ri_jalr, rd, rs1, imm);
}

int r_lui(r_reg rd, int imm)
{
	return r_encode_U(ri_lui, rd, imm);
}

int r_auipc(r_reg rd, int imm)
{
	return r_encode_U(ri_auipc, rd, imm);
}

int r_ecall()
{
	return r_encode_I(ri_ecall, r_zero, r_zero, 0);
}

int r_ebreak()
{
	return r_encode_I(ri_ebreak, r_zero, r_zero, 1);
}

int r_nop()
{
	return r_addi(r_zero, r_zero, 0);
}

int r_mul(r_reg rd, r_reg rs1, r_reg rs2)
{
	return r_encode_R(ri_mul, rd, rs1, rs2);
}

int r_elf_machine()
{
	return 0xf3;
}

int r_elf_flags()
{
	return 0x5000200;
}

int r_dest_reg(int param_no)
{
	return param_no + 10;
}

int r_get_code_length(il_instr *ii)
{
	il_op op = ii->op;
	function_def *fn;
	block_def *bd;

	switch (op) {
	case op_entry_point:
		fn = find_function(ii->string_param1);
		return 16 + (fn->num_params << 2);
	case op_function_call:
	case op_pointer_call:
		if (ii->param_no != 0)
			return 8;
		return 4;
	case op_load_numeric_constant:
		if (ii->int_param1 > -2048 && ii->int_param1 < 2047)
			return 4;
		else
			return 8;
	case op_block_start:
	case op_block_end:
		bd = &_blocks[ii->int_param1];
		if (bd->next_local > 0)
			return 4;
		else
			return 0;
	case op_equals:
	case op_not_equals:
	case op_less_than:
	case op_less_eq_than:
	case op_greater_than:
	case op_greater_eq_than:
		return 16;
	case op_syscall:
		return 20;
	case op_exit_point:
		return 16;
	case op_exit:
		return 12;
	case op_load_data_address:
	case op_jz:
	case op_jnz:
	case op_push:
	case op_pop:
	case op_get_var_addr:
	case op_start:
		return 8;
	case op_jump:
	case op_return:
	case op_generic:
	case op_add:
	case op_sub:
	case op_mul:
	case op_read_addr:
	case op_write_addr:
	case op_log_or:
	case op_log_and:
	case op_not:
	case op_bit_or:
	case op_bit_and:
	case op_negate:
	case op_bit_lshift:
	case op_bit_rshift:
		return 4;
	case op_label:
		return 0;
	default:
		error("Unsupported IL op");
	}
	return 0;
}

void r_op_load_data_address(backend_state *state, int ofs)
{
	ofs -= state->pc;
	c_emit(r_auipc(state->dest_reg, r_hi(ofs)));
	c_emit(r_addi(state->dest_reg, state->dest_reg, r_lo(ofs)));
}

void r_op_load_numeric_constant(backend_state *state, int val)
{
	if (val > -2048 && val < 2047) {
		c_emit(r_addi(state->dest_reg, r_zero, r_lo(val)));
	} else {
		c_emit(r_lui(state->dest_reg, r_hi(val)));
		c_emit(r_addi(state->dest_reg, state->dest_reg, r_lo(val)));
	}
}

void r_op_get_global_addr(backend_state *state, int ofs)
{
	/* need to find the variable offset in data section, from PC */
	ofs -= state->pc;
	c_emit(r_auipc(state->dest_reg, r_hi(ofs)));
	c_emit(r_addi(state->dest_reg, state->dest_reg, r_lo(ofs)));
}

void r_op_get_local_addr(backend_state *state, int offset)
{
	c_emit(r_addi(state->dest_reg, r_s0, 0));
	c_emit(r_addi(state->dest_reg, state->dest_reg, offset));
}

void r_op_get_function_addr(backend_state *state, int ofs)
{
	c_emit(r_lui(state->dest_reg, r_hi(ofs)));
	c_emit(r_addi(state->dest_reg, state->dest_reg, r_lo(ofs)));
}

void r_op_read_addr(backend_state *state, int len)
{
	switch (len) {
	case 4:
		c_emit(r_lw(state->dest_reg, state->op_reg, 0));
		break;
	case 1:
		c_emit(r_lb(state->dest_reg, state->op_reg, 0));
		break;
	default:
		error("Unsupported word size");
	}
}

void r_op_write_addr(backend_state *state, int len)
{
	switch (len) {
	case 4:
		c_emit(r_sw(state->dest_reg, state->op_reg, 0));
		break;
	case 1:
		c_emit(r_sb(state->dest_reg, state->op_reg, 0));
		break;
	default:
		error("Unsupported word size");
	}
}

void r_op_jump(int ofs)
{
	c_emit(r_jal(r_zero, ofs));
}

void r_op_return(int ofs)
{
	c_emit(r_jal(r_zero, ofs));
}

void r_op_function_call(backend_state *state, int ofs)
{
	c_emit(r_jal(r_ra, ofs));
	if (state->dest_reg != r_a0)
		c_emit(r_addi(state->dest_reg, r_a0, 0));
}

void r_op_pointer_call(backend_state *state)
{
	c_emit(r_jalr(r_ra, state->op_reg, 0));
	if (state->dest_reg != r_a0)
		c_emit(r_addi(state->dest_reg, r_a0, 0));
}

void r_op_push(backend_state *state)
{
	c_emit(r_addi(r_sp, r_sp, -16)); /* 16 aligned although we only need 4 */
	c_emit(r_sw(state->dest_reg, r_sp, 0));
}

void r_op_pop(backend_state *state)
{
	c_emit(r_lw(state->dest_reg, r_sp, 0));
	c_emit(r_addi(r_sp, r_sp, 16)); /* 16 aligned although we only need 4 */
}

void r_op_exit_point()
{
	c_emit(r_addi(r_sp, r_s0, 16));
	c_emit(r_lw(r_ra, r_sp, -8));
	c_emit(r_lw(r_s0, r_sp, -4));
	c_emit(r_jalr(r_zero, r_ra, 0));
}

void r_op_alu(backend_state *state, il_op op)
{
	switch (op) {
	case op_add:
		c_emit(r_add(state->dest_reg, state->dest_reg, state->op_reg));
		break;
	case op_sub:
		c_emit(r_sub(state->dest_reg, state->dest_reg, state->op_reg));
		break;
	case op_mul:
		c_emit(r_mul(state->dest_reg, state->dest_reg, state->op_reg));
		break;
	case op_negate:
		c_emit(r_sub(state->dest_reg, r_zero, state->dest_reg));
		break;
	default:
		break;
	}
}

void r_op_cmp(backend_state *state, il_op op)
{
	switch (op) {
	case op_equals:
		c_emit(r_beq(state->dest_reg, state->op_reg, 12));
		break;
	case op_not_equals:
		c_emit(r_bne(state->dest_reg, state->op_reg, 12));
		break;
	case op_less_than:
		c_emit(r_blt(state->dest_reg, state->op_reg, 12));
		break;
	case op_greater_eq_than:
		c_emit(r_bge(state->dest_reg, state->op_reg, 12));
		break;
	case op_greater_than:
		c_emit(r_blt(state->op_reg, state->dest_reg, 12));
		break;
	case op_less_eq_than:
		c_emit(r_bge(state->op_reg, state->dest_reg, 12));
		break;
	default:
		error("Unsupported conditional IL op");
		break;
	}
	c_emit(r_addi(state->dest_reg, r_zero, 0));
	c_emit(r_jal(r_zero, 8));
	c_emit(r_addi(state->dest_reg, r_zero, 1));
}

void r_op_log(backend_state *state, il_op op)
{
	switch (op) {
	case op_log_and:
		/* we assume both have to be 1, they can't be just nonzero */
		c_emit(r_and(state->dest_reg, state->dest_reg, state->op_reg));
		break;
	case op_log_or:
		c_emit(r_or(state->dest_reg, state->dest_reg, state->op_reg));
		break;
	default:
		break;
	}
}

void r_op_bit(backend_state *state, il_op op)
{
	switch (op) {
	case op_bit_and:
		c_emit(r_and(state->dest_reg, state->dest_reg, state->op_reg));
		break;
	case op_bit_or:
		c_emit(r_or(state->dest_reg, state->dest_reg, state->op_reg));
		break;
	case op_bit_lshift:
		c_emit(r_sll(state->dest_reg, state->dest_reg, state->op_reg));
		break;
	case op_bit_rshift:
		c_emit(r_srl(state->dest_reg, state->dest_reg, state->op_reg));
		break;
	case op_not:
		/* only works for small range integers */
		c_emit(r_sltiu(state->dest_reg, state->dest_reg, 1));
		break;
	default:
		break;
	}
}

void r_op_jz(backend_state *state, il_op op, int ofs)
{
	if (ofs >= -4096 && ofs <= 4095) {
		/* near jump (branch) */
		if (op == op_jz) {
			c_emit(r_nop());
			c_emit(r_beq(state->dest_reg, r_zero, ofs));
		} else if (op == op_jnz) {
			c_emit(r_nop());
			c_emit(r_bne(state->dest_reg, r_zero, ofs));
		}
	} else {
		/* far jump */
		if (op == op_jz) {
			c_emit(r_bne(state->dest_reg, r_zero, 8)); /* skip next instruction */
			c_emit(r_jal(r_zero, ofs));
		} else if (op == op_jnz) {
			c_emit(r_beq(state->dest_reg, r_zero, 8));
			c_emit(r_jal(r_zero, ofs));
		}
	}
}

void r_op_block(int len)
{
	c_emit(r_addi(r_sp, r_sp, len));
}

void r_op_entry_point(int len)
{
	c_emit(r_addi(r_sp, r_sp, -16 - len));
	c_emit(r_sw(r_s0, r_sp, 12 + len));
	c_emit(r_sw(r_ra, r_sp, 8 + len));
	c_emit(r_addi(r_s0, r_sp, len));
}

void r_op_store_param(int pn, int ofs)
{
	c_emit(r_sw(r_a0 + pn, r_s0, ofs));
}

void r_op_start()
{
	c_emit(r_lw(r_a0, r_sp, 0)); /* argc */
	c_emit(r_addi(r_a1, r_sp, 4)); /* argv */
}

void r_op_syscall()
{
	c_emit(r_addi(r_a7, r_a0, 0));
	c_emit(r_addi(r_a0, r_a1, 0));
	c_emit(r_addi(r_a1, r_a2, 0));
	c_emit(r_addi(r_a2, r_a3, 0));
	c_emit(r_ecall());
}

void r_op_exit()
{
	c_emit(r_addi(r_a0, r_zero, 0));
	c_emit(r_addi(r_a7, r_zero, 93));
	c_emit(r_ecall());
}

void r_initialize_backend(backend_def *be)
{
	be->arch = a_riscv;
	be->source_define = "__RISCV";
	be->elf_machine = r_elf_machine;
	be->elf_flags = r_elf_flags;
	be->c_dest_reg = r_dest_reg;
	be->c_get_code_length = r_get_code_length;
	be->op_load_data_address = r_op_load_data_address;
	be->op_load_numeric_constant = r_op_load_numeric_constant;
	be->op_get_global_addr = r_op_get_global_addr;
	be->op_get_local_addr = r_op_get_local_addr;
	be->op_get_function_addr = r_op_get_function_addr;
	be->op_read_addr = r_op_read_addr;
	be->op_write_addr = r_op_write_addr;
	be->op_jump = r_op_jump;
	be->op_return = r_op_return;
	be->op_function_call = r_op_function_call;
	be->op_pointer_call = r_op_pointer_call;
	be->op_push = r_op_push;
	be->op_pop = r_op_pop;
	be->op_exit_point = r_op_exit_point;
	be->op_alu = r_op_alu;
	be->op_cmp = r_op_cmp;
	be->op_log = r_op_log;
	be->op_bit = r_op_bit;
	be->op_jz = r_op_jz;
	be->op_block = r_op_block;
	be->op_entry_point = r_op_entry_point;
	be->op_store_param = r_op_store_param;
	be->op_start = r_op_start;
	be->op_syscall = r_op_syscall;
	be->op_exit = r_op_exit;
}


int main(int argc, char *argv[])
{
	int i = 1;/* clib = 1; */
	char *outfile = NULL, *infile = NULL;

	printf("rvcc C compiler\n");

	while (i < argc) {
		if (strcmp(argv[i], "-noclib") == 0)
			/*clib = 0;*/
			break;
		else if (strcmp(argv[i], "-o") == 0)
			if (i < argc + 1) {
				outfile = argv[i + 1];
				i++;
			} else {
				abort();
			}
		else
			infile = argv[i];
		i++;
	}

	if (infile == NULL) {
		printf("Missing source file!\n");
		printf("Usage: rvcc [-o outfile] [-noclib] [-march=riscv|arm] <infile.c>\n");
		return -1;
	}

	/* initialize globals */
	g_initialize();

	/* include clib 
	// if (clib) {
	// 	s_clib();
	// }
*/
	/* load source code */
	s_load(infile);

	printf("Loaded %d source bytes\n", _source_idx);

	r_initialize_backend(_backend);
	

	/* parse source into IL */
	p_parse();

	printf("Parsed into %d IL instructions\n", _il_idx);

	/* generate code from IL */
	c_generate();

	printf("Compiled into %d code bytes and %d data bytes\n", _e_code_idx, _e_data_idx);

	/* output code in ELF */
	e_generate(outfile);

	return 0;
}
