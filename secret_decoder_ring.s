# Author Joseph Mbabu
# secret_decoder_ring.s
# Encryption using Caesar cipher

# Feb 14, 2016

.data
message_prompt: .asciiz "Enter a message: "
message: .space 255 # message buffer
result: .space 255 # holds the encrypted/decrypted message

done: .asciiz "stop\n" # compared to input to indicate when done

key_prompt: .asciiz "Enter the key for this message: "
key: .word 0 # holds message key

task_prompt: .asciiz "(e)ncypt or (d)ecrypt ? "
command: .space 255 # holds command(encrypt or decrypt)

empty_line: .asciiz "\n"
next_line: .asciiz "\n\n"      #two new lines

invalid_key_msg: .asciiz "Err. Encrption key out of bounds. Enter key 0-26.\n"
_invalid_msg:    .asciiz "Err. Input message contains invalid characters.\n"
decrypting: .asciiz "Decrypting...\n"
exit_msg: .asciiz "Goodbye!"   # displayed before program terminates

.text
###############
# Procedure: _print_string
# Purpose: Prints a string to console
# Arguments: $a0 - contains the address of the string to print
# Returned values: none
###############
_print_string:
	li $v0, 4
	syscall
	jr $ra

###############
# Procedure: _get_input
# Purpose: Gets string-input from console
# Arguments: None
# Returned values: $v0 input from console
###############
_get_input:
	li $v0, 8
	syscall
	jr $ra

###########
# Procedure: _get_key
# Purpose: Gets message-key
# Arguments: none
# Returned values: $v0 - input from the console
##########
_get_key:
	li $v0, 5
	syscall
	jr $ra

###########
# Procedure: _encrypt
# Purpose: Encrypts message using provided key
# Arguments: $a0 - the address of message and, $a1 - encryption key
# Returned values: None
##########
_encrypt:
    li $s1, 122       # char z to check upper
    li $s0, 123       # load char '{'

	beq $t0, $zero, _done
	lb $t2, 0($t1)  # get next character from message string
	li $t4, 32      # load space character
	beq $t4, $t2, encryption_helper # if character is white-space
	beqz $t2, _done    # check for the end of string using null character
	add $t3, $t2, $t0  # shift character by key value

	slt $t9,  $t3,  $s0
	beq $t9, $zero, l1      # if $t2 > z, round down

    f1:                # return here after fixing boundary
	sb $t3, 0($t1)     # store encrypted character
	addi $t1, $t1, 1   # increment pointer to point to next position
	j _encrypt

encryption_helper:
	add $t3, $t2, $zero # if char is a space, add nothing to it
	sb $t3, 0($t1)      # push character on string
	addi $t1, $t1, 1    # increment pointer to point to next position
	j _encrypt
	l1:
	    li $s4, 96
		sub $s3, $t3, $s1    # difference btw char and upper limimt
		add $t3, $s4, $s3
    j f1

###########
# Procedure: _decrypt
# Purpose: Encrypts message using provided key
# Arguments: $a0 - the address of message and, $a1 - decryption key
# Returned values: None
###########
_decrypt:
    li $s0, 96        # char ''' to check lower boundary
    li $s1, 97        # load char 'a'
    li $s2, 10        # load new character

	beq $t0, $zero, _all_possible_messages   # if key == 0 display all possible input messages
	lb $t2, 0($t1)  # get next character from message string
	li $t4, 32      # load space character
	beq $t4, $t2, decryption_helper # if character is white-space
	beq $t2, $s2, _done    # check for null character
	sub $t3, $t2, $t0  # shift character by key value

	slt $t9, $t3, $s1
	bne $t9, $zero, l2  # if $t2 < a

    f2:                # return here after fixing boundary issues
	sb $t3, 0($t1)     # store encrypted character
	addi $t1, $t1, 1   # increment pointer to point to next position
	j _decrypt
decryption_helper:
	add $t3, $t2, $zero # if char is a space, add nothing to it
	sb $t3, 0($t1)      # push char back on string
	addi $t1, $t1, 1
	j _decrypt
	l2:
	    li $s4, 123
		sub $s3, $s1, $t3    # difference btw char and upper limimt
		sub $t3, $s4, $s3
    j f2


###########
# Procedure: _all_possible messages
# Purpose: Outputs input messages for every posssible encryption key
##########
_all_possible_messages:
	la $a0, decrypting
	jal _print_string
	li $s0, 97        # char 'a', to check lower boundary
    li $s1, 122       # char 'z'  to check upper boundary
    li $s2, 1         # count number of possible input messages
    li $s4, 26        # when to stop
    li $s5, 123
    li $s6, 10
_loop:
	la $t1, message
_all:
	lb $t2, 0($t1) 		# get next character from message string
	li $t4, 32     	    # load whitespace character

	beq $t4, $t2, is_whitespace   # if character is whitespace
 	beq $t2, $s6, _complete           # if it's a null char; end of string

 	sub $t2, $t2, $t0             # decrypt character

	slt $t9, $t2, $s0
	bne $t9, $zero, lower_limit   # if $t2 < a

	slt $t9,  $t2,  $s1
	beq $t9, $zero, upper_limit      # if $t2 > z

	limit:                    #return here after characters out of limits
	slt $t8, $t2, $zero,      # if value in $t8 is less than zero,
	bne $t8, $zero, all_done  # all possible input messages have been displayed
	sb  $t2, 0($t1)           # push decrypted character back to string=
	addi $t1, $t1, 1          # increment string pointer
	j _all

	_complete:
		slt $t0, $t0, $zero    # key++
		bne $t0, $zero, increment_key
    	key_value_incremented:

		la $a0, message      # load possible message
		jal _print_string    # print message to console

    	exit_loop:
    		beq $s2, $s4 all_done
    	addi $t0, $t0, 1     # key++
    	addi $s2, $s2, 1     # count++
    	j _loop

	##################
	# helper functions
	##################
	lower_limit:
		sub $s3, $s0, $t2    # difference btw char and lower limit
    	sub $t2, $s5, $s3    # difference btw $s3 and upper limit
    	j limit

	upper_limit:
		sub $s3, $t2, $s1    # difference btw char and upper limimt
    	add $t2, $s0, $s3    # add to lower limit
    	j limit

	increment_key:           # encryption_key++
		addi $t0, $t0, 1
		j key_value_incremented

	is_whitespace:
		add $t3, $t2, $zero # if char is a space, add nothing to it
		sb $t3, 0($t1)      # push character back on string
		addi $t1, $t1, 1
		j _all

	is_done:
		lb $t6, 0($t1)
		lb $t7, 0($t5)
		bne $t6, $t7 not_done       # if characters are not equal
		beqz $t6, _break_while_loop # exit program if input string matches "stop"
		addi $t1, $t1, 1            # increment pointer to point to next position
		addi $t5, $t5, 1            # increment string pointer
		j is_done

    validate_input_message:
    	li $s0, 96    # lower bound; char '''
    	li $s1, 123   # upper bound; char 'z'
    	li $s2, 32    # load whitespace character
        li $s3, 10    # new line character
    	loop:
    		lb $t2, 0($t1)        # get next character from message string
    		beq $t2, $s3, message_okay
    		beq $s2, $t2, whitespace_okay  # allow whitespaces

    		slt $t3, $t2, $s0      # if char < a
    		bne $t3, $zero, invalid_message

    		slt $t3,  $t2,  $s1
			beq $t3, $zero, invalid_message  # if $t2 > z, round down
			whitespace_okay:
		    addi $t1, $t1, 1                 # increment pointer to point to next position
		    j loop
        invalid_message:
            li $v0, 4
        	la $a0 _invalid_msg
        	syscall
        	j get_message

	_new_line:  # prints two empty lines to console
		li $v0, 4
		la $a0, next_line
		syscall
    	jr $ra


 	_invalid_key: # prompt for encryption key again
    	la $a0, invalid_key_msg
    	jal _print_string
    	j get_key


###############
# Procedure: Main
# Purpose: Starting point of the program
# Arguments: None
# Returned values: None
##############
main:
while_loop:
	# prompt for message string
	get_message:
	la, $a0, message_prompt
	jal _print_string

    # get message string
    li $v0, 8
    la $a0, message
    li $a1, 255    # max length of input string
    syscall

    la $t1, message          # load message address into $t1

    la $t5, done     # load flag in $t5
    j is_done
    not_done:

    j validate_input_message # validate message
    message_okay:            # return here if message is valid


    get_key: # return here if invalid encryption key is provided

    la $a0, key_prompt # prompt for the encryption/decryption key
    jal _print_string

    # get key
    jal _get_key
    sw $v0, key

    # load encrypt/decrypt key into $t0
    lw $t0, key
    # validate encryption key
    validate_key:
		li $t1, 27
		slt $t2,  $t0, $t1
		beq $t2, $zero, _invalid_key # if key > 26
        slt $t2,  $t0, $zero
		bne $t2, $zero, _invalid_key # if key < 0

    la $t1, message  # load message address into $t1
    move $s6, $t1    # copy address of $t1 into $s6
    la $t5, done     # load flag in $t5

    # encrypt or decypt message?
    la $a0, task_prompt
    jal _print_string

    # get command
    li $v0, 8
    la $a0, command
    syscall

    li $s0, 'e'
    li $s1, 'd'
    lb $s2, command

    beq $s0, $s2, _encrypt # if command equals 'e' branch to _encrpt procedure
    beq $s1, $s2, _decrypt # if command equals 'd' branch to _decrypt procedure

    _done:  # return here when done with encryption or decryption

    la $a0, message
    jal _print_string

    jal _new_line
    all_done:      # return here after decrypting all possible input messages
    j while_loop   # jumpt to beginning of while_loop

_break_while_loop:
	la $a0, exit_msg
	jal _print_string # display 'Goodbye' to console before exiting
	li $v0, 10
	syscall
