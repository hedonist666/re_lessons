pushad;
call routine;
routine:
    pop ebp;
    sub ebp, routine;
    push 0x00000010;
    lea eax, [ebp + szCaption];
    push eax;
    lea eax, [ebp+szText];
    push eax;
    push 0;
    popad;
    mov eax, 0xAAAAAAAA;
    ret;
szText:
    db('S');
    db('o');
    db('s');
    db('i');
    db('t');
    db('e');
    db('h');
    db('u');
    db('i');
    db(0);
szCaption:
    db('p');
    db('i');
    db('d');
    db('a');
    db('r');
    db('a');
    db('z');
    db('y');
    db(0);


