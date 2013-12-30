/* From Rusty Russell's CCAN, License CC0 (Public Domain)
 * See CC0-License in top level directory
 */

#ifndef _CONTAINER_OF_H
#define _CONTAINER_OF_H

#define check_types_match(expr1, expr2)			\
	((typeof(expr1) *)0 != (typeof(expr2) *)0)

#define container_of(member_ptr, containing_type, member)		\
	((containing_type *)						\
	  ((char *)(member_ptr) - offsetof(containing_type, member))	\
	  - check_types_match(*(member_ptr), ((containing_type *)0)->member))

#endif
