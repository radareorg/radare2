{
 "cells": [
  {
   "cell_type": "code",
   "execution_count": 11,
   "metadata": {},
   "outputs": [],
   "source": [
    "import os"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 36,
   "metadata": {},
   "outputs": [],
   "source": [
    "ops = ['FCMOVE',\t\n",
    "'FCMOVBE',\t\n",
    "'FCMOVU',\t\n",
    "'FCMOVNB',\t\n",
    "'FCMOVNE',\t\n",
    "'FCMOVNBE',\n",
    "'FCMOVNU']\n",
    "def nasm(stmt):\n",
    "    out = os.popen(\"rasm2 -b 64 -a x86.nasm '\" + stmt+ \"'\").read()\n",
    "    return \"a \\\"{}\\\" {}\".format(stmt, out)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 20,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "a \"fcmove st0, st1\" dac9\n",
      "a \"fcmovbe st0, st1\" dad1\n",
      "a \"fcmovu st0, st1\" dad9\n",
      "a \"fcmovnb st0, st1\" dbc1\n",
      "a \"fcmovne st0, st1\" dbc9\n",
      "a \"fcmovnbe st0, st1\" dbd1\n",
      "a \"fcmovnu st0, st1\" dbd9\n"
     ]
    }
   ],
   "source": [
    "for op in ops:\n",
    "    stmt = op.lower() + \" st0, st1\"\n",
    "    #print(stmt)\n",
    "    out = os.popen(\"rasm2 -a x86.nasm '\" + stmt+ \"'\").read()\n",
    "    print(\"a \\\"{}\\\" {}\".format(stmt, out),end=\"\")"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 23,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "a \"ffree st0\" ddc0\n",
      "a \"ffree st(7)\" "
     ]
    }
   ],
   "source": [
    "ops = [\"ffree\"]\n",
    "regs = [\"st0\", \"st7\"]\n",
    "for op in ops:\n",
    "    for reg in regs:\n",
    "        stmt = op.lower() + \" \" + reg\n",
    "        out = os.popen(\"rasm2 -a x86.nasm '\" + stmt+ \"'\").read()\n",
    "        print(\"a \\\"{}\\\" {}\".format(stmt, out),end=\"\")"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 54,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "a \"fdiv dword[rax]\" d830\n",
      "a \"fdiv qword [rax]\" dc30\n",
      "a \"fdiv st0, st7\" d8f7\n",
      "a \"fdiv st6, st0\" dcfe\n",
      "a \"fdivp\" def9\n",
      "a \"fdivp st2, st0\" defa\n",
      "a \"fidiv word [rax]\" de30\n",
      "a \"fidiv dword [rax]\" da30\n"
     ]
    }
   ],
   "source": [
    "stmts = [\"fdiv dword[rax]\", \"fdiv qword [rax]\", \"fdiv st0, st7\", \"fdiv st6, st0\", \"fdivp\", \"fdivp st2, st0\",\"fidiv word [rax]\", \"fidiv dword [rax]\"]\n",
    "for s in stmts:\n",
    "    print(nasm(s),end=\"\")"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 56,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "a \"fdivr dword[rax]\" d838\n",
      "a \"fdivr qword [rax]\" dc38\n",
      "a \"fdivr st0, st7\" d8ff\n",
      "a \"fdivr st6, st0\" dcf6\n",
      "a \"fdivrp\" def1\n",
      "a \"fdivrp st2, st0\" def2\n",
      "a \"fidivr word [rax]\" de38\n",
      "a \"fidivr dword [rax]\" da38\n"
     ]
    }
   ],
   "source": [
    "stmts = [\"fdivr dword[rax]\", \"fdivr qword [rax]\", \"fdivr st0, st7\", \"fdivr st6, st0\", \"fdivrp\", \"fdivrp st2, st0\",\"fidivr word [rax]\", \"fidivr dword [rax]\"]\n",
    "for s in stmts:\n",
    "    print(nasm(s),end=\"\")"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 58,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "a \"fmul dword[rax]\" d808\n",
      "a \"fmul qword [rax]\" dc08\n",
      "a \"fmul st0, st7\" d8cf\n",
      "a \"fmul st6, st0\" dcce\n",
      "a \"fmulp\" dec9\n",
      "a \"fmulp st2, st0\" deca\n",
      "a \"fimul word [rax]\" de08\n",
      "a \"fimul dword [rax]\" da08\n"
     ]
    }
   ],
   "source": [
    "stmts = [\"fdivr dword[rax]\", \"fdivr qword [rax]\", \"fdivr st0, st7\", \"fdivr st6, st0\", \"fdivrp\", \"fdivrp st2, st0\",\"fidivr word [rax]\", \"fidivr dword [rax]\"]\n",
    "stmts = [s.replace(\"divr\", \"mul\") for s in stmts]\n",
    "for s in stmts:\n",
    "    print(nasm(s),end=\"\")"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 59,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "a \"fsub dword[rax]\" d820\n",
      "a \"fsub qword [rax]\" dc20\n",
      "a \"fsub st0, st7\" d8e7\n",
      "a \"fsub st6, st0\" dcee\n",
      "a \"fsubp\" dee9\n",
      "a \"fsubp st2, st0\" deea\n",
      "a \"fisub word [rax]\" de20\n",
      "a \"fisub dword [rax]\" da20\n"
     ]
    }
   ],
   "source": [
    "stmts = [\"fdivr dword[rax]\", \"fdivr qword [rax]\", \"fdivr st0, st7\", \"fdivr st6, st0\", \"fdivrp\", \"fdivrp st2, st0\",\"fidivr word [rax]\", \"fidivr dword [rax]\"]\n",
    "stmts = [s.replace(\"divr\", \"sub\") for s in stmts]\n",
    "for s in stmts:\n",
    "    print(nasm(s),end=\"\")"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 60,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "a \"fsubr dword[rax]\" d828\n",
      "a \"fsubr qword [rax]\" dc28\n",
      "a \"fsubr st0, st7\" d8ef\n",
      "a \"fsubr st6, st0\" dce6\n",
      "a \"fsubrp\" dee1\n",
      "a \"fsubrp st2, st0\" dee2\n",
      "a \"fisubr word [rax]\" de28\n",
      "a \"fisubr dword [rax]\" da28\n"
     ]
    }
   ],
   "source": [
    "stmts = [\"fdivr dword[rax]\", \"fdivr qword [rax]\", \"fdivr st0, st7\", \"fdivr st6, st0\", \"fdivrp\", \"fdivrp st2, st0\",\"fidivr word [rax]\", \"fidivr dword [rax]\"]\n",
    "stmts = [s.replace(\"divr\", \"subr\") for s in stmts]\n",
    "for s in stmts:\n",
    "    print(nasm(s),end=\"\")"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 62,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "a \"paddw mm0, mm0\" 0ffdc0\n",
      "a \"paddw mm0, mm1\" 0ffdc1\n",
      "a \"paddw mm0, mm2\" 0ffdc2\n",
      "a \"paddw mm0, mm3\" 0ffdc3\n",
      "a \"paddw mm0, mm4\" 0ffdc4\n",
      "a \"paddw mm0, mm5\" 0ffdc5\n",
      "a \"paddw mm0, mm6\" 0ffdc6\n",
      "a \"paddw mm0, mm7\" 0ffdc7\n",
      "a \"paddw mm1, mm0\" 0ffdc8\n",
      "a \"paddw mm1, mm1\" 0ffdc9\n",
      "a \"paddw mm1, mm2\" 0ffdca\n",
      "a \"paddw mm1, mm3\" 0ffdcb\n",
      "a \"paddw mm1, mm4\" 0ffdcc\n",
      "a \"paddw mm1, mm5\" 0ffdcd\n",
      "a \"paddw mm1, mm6\" 0ffdce\n",
      "a \"paddw mm1, mm7\" 0ffdcf\n",
      "a \"paddw mm2, mm0\" 0ffdd0\n",
      "a \"paddw mm2, mm1\" 0ffdd1\n",
      "a \"paddw mm2, mm2\" 0ffdd2\n",
      "a \"paddw mm2, mm3\" 0ffdd3\n",
      "a \"paddw mm2, mm4\" 0ffdd4\n",
      "a \"paddw mm2, mm5\" 0ffdd5\n",
      "a \"paddw mm2, mm6\" 0ffdd6\n",
      "a \"paddw mm2, mm7\" 0ffdd7\n",
      "a \"paddw mm3, mm0\" 0ffdd8\n",
      "a \"paddw mm3, mm1\" 0ffdd9\n",
      "a \"paddw mm3, mm2\" 0ffdda\n",
      "a \"paddw mm3, mm3\" 0ffddb\n",
      "a \"paddw mm3, mm4\" 0ffddc\n",
      "a \"paddw mm3, mm5\" 0ffddd\n",
      "a \"paddw mm3, mm6\" 0ffdde\n",
      "a \"paddw mm3, mm7\" 0ffddf\n",
      "a \"paddw mm4, mm0\" 0ffde0\n",
      "a \"paddw mm4, mm1\" 0ffde1\n",
      "a \"paddw mm4, mm2\" 0ffde2\n",
      "a \"paddw mm4, mm3\" 0ffde3\n",
      "a \"paddw mm4, mm4\" 0ffde4\n",
      "a \"paddw mm4, mm5\" 0ffde5\n",
      "a \"paddw mm4, mm6\" 0ffde6\n",
      "a \"paddw mm4, mm7\" 0ffde7\n",
      "a \"paddw mm5, mm0\" 0ffde8\n",
      "a \"paddw mm5, mm1\" 0ffde9\n",
      "a \"paddw mm5, mm2\" 0ffdea\n",
      "a \"paddw mm5, mm3\" 0ffdeb\n",
      "a \"paddw mm5, mm4\" 0ffdec\n",
      "a \"paddw mm5, mm5\" 0ffded\n",
      "a \"paddw mm5, mm6\" 0ffdee\n",
      "a \"paddw mm5, mm7\" 0ffdef\n",
      "a \"paddw mm6, mm0\" 0ffdf0\n",
      "a \"paddw mm6, mm1\" 0ffdf1\n",
      "a \"paddw mm6, mm2\" 0ffdf2\n",
      "a \"paddw mm6, mm3\" 0ffdf3\n",
      "a \"paddw mm6, mm4\" 0ffdf4\n",
      "a \"paddw mm6, mm5\" 0ffdf5\n",
      "a \"paddw mm6, mm6\" 0ffdf6\n",
      "a \"paddw mm6, mm7\" 0ffdf7\n",
      "a \"paddw mm7, mm0\" 0ffdf8\n",
      "a \"paddw mm7, mm1\" 0ffdf9\n",
      "a \"paddw mm7, mm2\" 0ffdfa\n",
      "a \"paddw mm7, mm3\" 0ffdfb\n",
      "a \"paddw mm7, mm4\" 0ffdfc\n",
      "a \"paddw mm7, mm5\" 0ffdfd\n",
      "a \"paddw mm7, mm6\" 0ffdfe\n",
      "a \"paddw mm7, mm7\" 0ffdff\n"
     ]
    }
   ],
   "source": [
    "op = \"paddw\"\n",
    "regs = [\"mm\" + str(i) for i in range(8)]\n",
    "for r1 in regs:\n",
    "    for r2 in regs:\n",
    "        stmt = op + \" \" + r1 + \", \" + r2\n",
    "        out = os.popen(\"rasm2 -a x86.nasm '\" + stmt+ \"'\").read()\n",
    "        print(\"a \\\"{}\\\" {}\".format(stmt, out),end=\"\")"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "metadata": {},
   "outputs": [],
   "source": []
  }
 ],
 "metadata": {
  "kernelspec": {
   "display_name": "Python 3",
   "language": "python",
   "name": "python3"
  },
  "language_info": {
   "codemirror_mode": {
    "name": "ipython",
    "version": 3
   },
   "file_extension": ".py",
   "mimetype": "text/x-python",
   "name": "python",
   "nbconvert_exporter": "python",
   "pygments_lexer": "ipython3",
   "version": "3.5.3"
  }
 },
 "nbformat": 4,
 "nbformat_minor": 2
}
