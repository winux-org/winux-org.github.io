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
