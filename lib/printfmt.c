// Stripped-down primitive printf-style formatting routines,
// used in common by printf, sprintf, fprintf, etc.
// This code is also used by both the kernel and user programs.

#include <inc/types.h>
#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/stdarg.h>
#include <inc/error.h>

/*
 * Space or zero padding and a field width are supported for the numeric
 * formats only.
 *
 * The special format %e takes an integer error code
 * and prints a string describing the error.
 * The integer may be positive or negative,
 * so that -E_NO_MEM and E_NO_MEM are equivalent.
 */

int color = 0x0700; // console_color

static const char * const error_string[MAXERROR] =
{
	[E_UNSPECIFIED]	= "unspecified error",
	[E_BAD_ENV]	= "bad environment",
	[E_INVAL]	= "invalid parameter",
	[E_NO_MEM]	= "out of memory",
	[E_NO_FREE_ENV]	= "out of environments",
	[E_FAULT]	= "segmentation fault",
	[E_IPC_NOT_RECV]= "env is not recving",
	[E_EOF]		= "unexpected end of file",
};

/*
 * Print a number (base <= 16) in reverse order,
 * using specified putch function and associated pointer putdat.
 */
//
// @TODO why print_num() works, it should be printed in reverse order

static int num_length = 0; // indicate the number of layers(actually the how many bits of the number)
// Return the width for padding (actually padding width + 1)
static void
rprintnum(void (*putch)(int, void*), void *putdat,
	 unsigned long long num, unsigned base, int width, int padc)
{
    num_length++;
	// first recursively print all preceding (more significant) digits
	if (num >= base) {
		rprintnum(putch, putdat, num / base, base, width - 1, padc);
	} else if (padc != '-') {
		// print any needed pad characters before first digit
		while (--width > 0)
			putch(padc, putdat);
	}

	// then print this (the least significant) digit
	putch("0123456789abcdef"[num % base], putdat);
}


static void
printnum(void (*putch)(int, void*), void *putdat,
	 unsigned long long num, unsigned base, int width, int padc)
{
	// if cprintf'parameter includes pattern of the form "%-", padding
	// space on the right side if neccesary.
	// you can add helper function if needed.
	// your code here:
    rprintnum(putch, putdat, num, base, width, padc);

    int rest_width = width - num_length;
    // @FIXME why can not get the right number?
	// putch("0123456789abcdef"[rest_width % base], putdat);
	if (padc == '-') {
        for(; rest_width>0; rest_width--)
		/* while (rest_width-- > 0) // --a && a-- is different */
			putch(' ', putdat);
    }
}

// Get an unsigned int of various possible sizes from a varargs list,
// depending on the lflag parameter.
static unsigned long long
getuint(va_list *ap, int lflag)
{
	if (lflag >= 2)
		return va_arg(*ap, unsigned long long);
	else if (lflag)
		return va_arg(*ap, unsigned long);
	else
		return va_arg(*ap, unsigned int);
}

// Same as getuint but signed - can't use getuint
// because of sign extension
static long long
getint(va_list *ap, int lflag)
{
	if (lflag >= 2)
		return va_arg(*ap, long long);
	else if (lflag)
		return va_arg(*ap, long);
	else
		return va_arg(*ap, int);
}


// Main function to format and print a string.
void printfmt(void (*putch)(int, void*), void *putdat, const char *fmt, ...);

static int ansi_to_cga_color[] = { // console_color
    0, // black
    4, // red
    2, // green
    7, // yellow
    1, // blue
    5, // magenta
    3, // cyan
    7, // white
};

void
vprintfmt(void (*putch)(int, void*), void *putdat, const char *fmt, va_list ap)
{
	register const char *p;
	register int ch, err;
	unsigned long long num;
	int base, lflag, width, precision, altflag, color_num;
	char padc;

	while (1) {
		while ((ch = *(unsigned char *) fmt++) != '%') {
			if (ch == '\0')
				return;
            else if (ch == '[') {  // ANSI escape sequence
                ch = *(unsigned char *) fmt++;
                while (ch != 'm') {
                    color_num = 0;
                    while (ch >= '0' && ch <= '9') {
                        color_num = color_num * 10 + ch - '0';
                        ch = *(unsigned char *) fmt++;
                    }
                    if (color_num >= 30 && color_num <= 37) {
                        // foreground color
                        color_num -= 30;
                        color &= 0xF0FF;
                        color |= (ansi_to_cga_color[color_num] << 8);
                    } else if (color_num >= 40 && color_num <= 47) {
                        // background color
                        color_num -= 40;
                        color &= 0xFFF;
                        color |= (ansi_to_cga_color[color_num] << 12);
                    }
                    if (ch == ';') {
                        ch = *(unsigned char *) fmt++;
                    }
                }
            } else
                putch(ch | color, putdat);
		}

		// Process a %-escape sequence
		padc = ' ';
		width = -1;
		precision = -1;
		lflag = 0;
		altflag = 0;
	reswitch:
		switch (ch = *(unsigned char *) fmt++) {

		// flag to pad on the right
		case '-':
			padc = '-';
			goto reswitch;

		// flag to pad with 0's instead of spaces
		case '0':
			padc = '0';
			goto reswitch;

		// width field
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			for (precision = 0; ; ++fmt) {
				precision = precision * 10 + ch - '0';
				ch = *fmt;
				if (ch < '0' || ch > '9')
					break;
			}
			goto process_precision;

		case '*':
			precision = va_arg(ap, int);
			goto process_precision;

		case '.':
			if (width < 0)
				width = 0;
			goto reswitch;

		case '#':
			altflag = 1;
			goto reswitch;

		process_precision:
			if (width < 0)
				width = precision, precision = -1;
			goto reswitch;

		// long flag (doubled for long long)
		case 'l':
			lflag++;
			goto reswitch;

		// character
		case 'c':
			putch(va_arg(ap, int) | color, putdat);
			break;

		// error message
		case 'e':
			err = va_arg(ap, int);
			if (err < 0)
				err = -err;
			if (err >= MAXERROR || (p = error_string[err]) == NULL)
				printfmt(putch, putdat, "error %d", err);
			else
				printfmt(putch, putdat, "%s", p);
			break;

		// string
		case 's':
			if ((p = va_arg(ap, char *)) == NULL)
				p = "(null)";
			if (width > 0 && padc != '-')
				for (width -= strnlen(p, precision); width > 0; width--)
					putch(padc | color, putdat);
			for (; (ch = *p++) != '\0' && (precision < 0 || --precision >= 0); width--)
				if (altflag && (ch < ' ' || ch > '~'))
					putch('?' | color, putdat);
				else
					putch(ch | color, putdat);
			for (; width > 0; width--)
				putch(' ' | color, putdat);
			break;

		// (signed) decimal
		case 'd':
			num = getint(&ap, lflag);
			if ((long long) num < 0) {
				putch('-' | color, putdat);
				num = -(long long) num;
			}
			base = 10;
			goto number;

		// unsigned decimal
		case 'u':
			num = getuint(&ap, lflag);
			base = 10;
			goto number;

		// (unsigned) octal
		case 'o':
			// Replace this with your code.
			// putch('0', putdat); -- should not be here :( weird
			num = getuint(&ap, lflag);
			base = 8;
			goto number;

		// pointer
		case 'p':
			putch('0', putdat);
			putch('x', putdat);
			num = (unsigned long long)
				(uintptr_t) va_arg(ap, void *);
			base = 16;
			goto number;

		// (unsigned) hexadecimal
		case 'x':
			num = getuint(&ap, lflag);
			base = 16;
		number:
            printnum(putch, putdat, num, base, width, padc);
            break;

        case 'n': {
            // You can consult the %n specifier specification of the C99 printf function
            // for your reference by typing "man 3 printf" on the console.
            //
            // Requirements:
            // Nothing printed. The argument must be a pointer to a signed char,
            // where the number of characters written so far is stored.
            //
           // hint:  use the following strings to display the error messages
            //        when the cprintf function ecounters the specific cases,
            //        for example, when the argument pointer is NULL
            //        or when the number of characters written so far
            //        is beyond the range of the integers the signed char type
            //        can represent.

            const char *null_error = "\nerror! writing through NULL pointer! (%n argument)\n";
            const char *overflow_error = "\nwarning! The value %n argument pointed to has been overflowed!\n";

            // Your code here
            // "p" is used for "%s"
            // Cause: %n here is different (it's used via char *)
            //
            // @NOTE well, i can not see any check for this code snippet
            if ((p = va_arg(ap, void *)) == NULL) { // (void *) is ok
                printfmt(putch, putdat, "%s", null_error);
                break;
            }
            if( (*(int *)putdat) > 127) {
                (*((unsigned char *)p)) = (*((unsigned char *)putdat));
                printfmt(putch, putdat, "%s", overflow_error);
                break;
            }

            (*((char *)p)) = (*((char *)putdat));

            break;
        }

		// escaped '%' character
		case '%':
			putch(ch | color, putdat);
			break;

		// unrecognized escape sequence - just print it literally
		default:
			putch('%' | color, putdat);
			for (fmt--; fmt[-1] != '%'; fmt--)
				/* do nothing */;
			break;
		}
	}
}

void
printfmt(void (*putch)(int, void*), void *putdat, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vprintfmt(putch, putdat, fmt, ap);
	va_end(ap);
}

struct sprintbuf {
	char *buf;
	char *ebuf;
	int cnt;
};

static void
sprintputch(int ch, struct sprintbuf *b)
{
	b->cnt++;
	if (b->buf < b->ebuf)
		*b->buf++ = ch;
}

int
vsnprintf(char *buf, int n, const char *fmt, va_list ap)
{
	struct sprintbuf b = {buf, buf+n-1, 0};

	if (buf == NULL || n < 1)
		return -E_INVAL;

	// print the string to the buffer
	vprintfmt((void*)sprintputch, &b, fmt, ap);

	// null terminate the buffer
	*b.buf = '\0';

	return b.cnt;
}

int
snprintf(char *buf, int n, const char *fmt, ...)
{
	va_list ap;
	int rc;

	va_start(ap, fmt);
	rc = vsnprintf(buf, n, fmt, ap);
	va_end(ap);

	return rc;
}
