



class val(object):
    #def __init__(self,id):
    #    self.id=id

    by_str={}
    by_id={}

    #def get_id(self):
    #    return self.id

    @staticmethod
    def next_id():
        id = 1<<len(val.by_id)
        #print("next_id=%x"%id)
        return id

    @staticmethod
    def register_obj(obj):
        val.by_str[obj.tostring()]=obj
        val.by_id[obj.id]=obj
        return obj

    @staticmethod
    def dump():
        for v in val.by_id.values():
            print("%02x: %s"%(v.id,v.tostring()))

class var(val):
    @staticmethod
    def m(name):
        if name in val.by_str:
            return val.by_str[name]
        return val.register_obj(var(name))

    def __init__(self, name):
        self.name=name
        self.id = val.next_id()

    def tostring(self):
        return self.name

    def tolatex(self):
        return self.name


class expr(val):
    @staticmethod
    def m(name, args):
        new = e(name,args)
        s = e.tostring()
        if s in val.by_str:
            return val.by_str[s]
        return val.register_obj(new)

    def __init__(self, name, args):
        self.name=name
        self.args = args
        self.id = val.next_id()

    def tostring(self):
        out = self.name+"("
        for a in args:
            out += a+","
        out = out[:-1]+")"
        return out

class e(val):
    @staticmethod
    def m(arg):
        new = e(arg)
        s = new.tostring()
        if s in val.by_str:
            return val.by_str[s]
        return val.register_obj(new)

    def __init__(self, arg):
        self.arg = arg
        self.id = val.next_id()

    def tostring(self):
        out = "e("+self.arg.tostring()+")"
        return out

    def tolatex(self):
        out = "E_{\Kb}("+self.arg.tolatex()+")"
        return out

class x(val):
    @staticmethod
    def m(*args):
        return x(*args)

    def __init__(self, *args):
        self.args = []
        mask=0
        for a in args:
            if a is not None:
                mask ^= a.id
                #print("%x -> %x"%(a.id,mask))
        bits = "{0:b}".format(mask)[::-1]
        #print("final mask=%x -> %s"%(mask,bits))
        for i in range(0,len(bits)):
            if bits[i]=='1':
                self.args.append(val.by_id[1<<i])
        #print(self.args)
        self.id = mask

    def tostring(self):
        out = ""
        for a in self.args:
            out += a.tostring()+"+"
        out = out[:-1]
        return out

    def tolatex(self):
        return " \oplus ".join(a.tolatex() for a in self.args)


def close_brackets(s):
    p=""
    for c in s:
        if c=="(":
            p+=")"
        if c==")":
            p=p[:-1]
    return p

def latex_printer(obj):
    s = obj.tolatex()
    lim=160
    if len(s)>lim:
        #s="{}&\\\\\n"+s+"\\\\"
        p = close_brackets(s[0:lim])
        s="{}&"+s[0:lim]+"..."+p
        s+="\\\\"
    else:
        s="{}&"+s+"\\\\"
    return s

def txt_printer(obj):
    return obj.tostring()



def spae_step(ct,pt,p):
    i0 = x.m(pt,p)
    i1 = e.m(i0)
    c = x.m(ct,i1)
    ct = x.m(ct,pt)
    pt= x.m(p,i1)
    return (ct,pt,c)

def v12g_init(k):
    CT_0 = e.m(k)
    PT_0 = x.m(CT_0,k)
    return (CT_0,PT_0)

def v12g_null_tag(k,CT_0,PT_0):
    return e.m(CT_0)

def v12i_null_tag(k,CT_0,PT_0):
    ones=var.m(names["ones"])
    kb = x.m(k,ones)
    return x.m(CT_0,e.m(x.m(PT_0,kb)))

def v12h_null_tag(k,CT_0,PT_0):
    ones=var.m(names["ones"])
    kb = x.m(k,ones)
    return x.m(PT_0,e.m(kb))   #k + Ek(k) + Ek(~k)

def v12j_null_tag(k,CT_0,PT_0):
    ones=var.m(names["ones"])
    kb = x.m(k,ones)
    return x.m(PT_0,e.m(x.m(x.m(CT_0,PT_0),kb)))   #k + Ek(k) + Ek(FF)

def v12i_init(k):
    PT_0 = e.m(k)
    cst0 = var.m("\\block{CST0}")
    CT_0 = x.m(cst0,k)
    return (CT_0,PT_0)



def v12g_tag(k,ct,pt):
    return x.m(ct,e.m(x.m(x.m(ct,pt))))

def v12h_tag(k,ct,pt,mlen,alen):
    padinfo = var.m("PadInfo(%d,%d)"%(mlen,alen))
    return x.m(ct,e.m(x.m(x.m(ct,pt),padinfo)))

def test(initializer=v12g_init,null_tag=v12h_null_tag,printer=latex_printer,verbose=True):
    print()
    latex = printer==latex_printer

    k=var.m(names["k"])
    (CT_0,PT_0) = initializer(k)

    tag_null = null_tag(k,CT_0,PT_0)
    ct=CT_0
    pt=PT_0


    ones=var.m(names["ones"])
    #cst0 = var.m("\\block{CST0}")
    #p_values = [None, ones, cst0, x.m(ones,cst0)]
    p_values = [None, ones]
    if latex:
        print("\\begin{align}")
        print("\\begin{split}")
        print("\CT_%d =%s"%(0,printer(ct)))
        print("\PT_%d =%s"%(0,printer(pt)))
        print("\TAG_{null}=%s\\\\"%(printer(tag_null)))
        print("\\end{split}")
        print("\\end{align}")
    else:
        print("CT_%d =%s"%(0,printer(ct)))
        print("PT_%d =%s"%(0,printer(pt)))
        print("TAG_null=%s"%(printer(tag_null)))
    for p in p_values:
        ct=CT_0
        pt=PT_0
        alen=0
        mlen=0

        if latex:
            print("\\begin{align}")
            print("\\begin{split}")
            print("\\\\")
        if p is None:
            print("\Pb_0  ={}&0")
        else:
            print("\Pb_0 =%s"%(printer(p)))
        for i in range(0,12):
            print("\\\\")
            (ct,pt,p) = spae_step(ct,pt,p)
            mlen+=16*8
            tag = v12h_tag(k,ct,pt,mlen,alen)
            if verbose:
                if latex:
                    print("\CT_%d =%s"%(i+1,printer(ct)))
                    print("\PT_%d =%s"%(i+1,printer(pt)))
                else:
                    print("CT_%d =%s"%(i+1,printer(ct)))
                    print("PT_%d =%s"%(i+1,printer(pt)))
            if latex:
                print("\Cb_%d  =%s"%(i,printer(p)))
                #print("\Cb_%d \oplus \TAG_{null} =%s"%(i,printer(x.m(p,tag_null))))
                #print("\TAG_%d =%s"%(i,printer(tag)))
                #print("\Cb_%d \oplus \TAG_%d =%s"%(i,i,printer(x.m(p,tag))))
                #print("\Cb_%d \oplus \TAG_%d + \TAG_{null}=%s"%(i,i,printer(x.m(tag_null,x.m(p,tag)))))
            else:
                print("Cb_%d  =%s"%(i,printer(p)))
                #print("Cb_%d + TAG_null =%s"%(i,printer(x.m(p,tag_null))))
                print("TAG_%d =%s"%(i,printer(tag)))
                print("Cb_%d + TAG_%d =%s"%(i,i,printer(x.m(p,tag))))
                #print("Cb_%d + TAG_%d + TAG_null =%s"%(i,i,printer(x.m(tag_null,x.m(p,tag)))))
        if latex:
            print("\\end{split}")
            print("\\end{align}")


def cx(initializer=v12g_init,printer=latex_printer,verbose=True):
    print()
    latex = printer==latex_printer

    k=var.m(names["k"])
    (CT_0,PT_0) = initializer(k)

    ct=CT_0
    pt=PT_0

    ones=var.m(names["ones"])

    p_values = [None]

    expressions = []
    for p in p_values:
        ct=CT_0
        pt=PT_0
        #skip it since we want to xor the Ci
        #expressions.append((ct,pt,p))
        for i in range(0,4):
            (ct,pt,p) = spae_step(ct,pt,p)
            #print(i,": ",printer(p))
            expressions.append((ct,pt,p))

    for i in range(0,1<<len(expressions)):
        bits = "{0:b}".format(i)[::-1]
        bitcnt=0
        terms=[]
        for b in range(0,len(bits)):
            if bits[b]=='1':
                bitcnt+=1
                terms.append(b)
        if bitcnt>1:
            expr=""
            expr_val=None
            for term in terms:
                n="\Cb_{%d}"%term
                v=expressions[term][2]
                #print(n,": ",printer(v))
                expr+=n+" \oplus "
                if expr_val is None:
                    expr_val = v
                else:
                    expr_val = x.m(expr_val,v)
            print(expr[:-8]," = ",printer(expr_val))





def cx_symb(printer=latex_printer,verbose=True):
    print()
    latex = printer==latex_printer

    CT_0=var.m("\CT_0")
    PT_0=var.m("\PT_0")

    p_values = [None]

    depth = 6

    expressions = []
    for p in p_values:
        ct=CT_0
        pt=PT_0
        #skip it since we want to xor the Ci
        expressions.append((ct,pt,p))
        for i in range(0,depth):
            (ct,pt,p) = spae_step(ct,pt,p)
            #print(i,": ",printer(p))
            expressions.append((ct,pt,p))

    term_names = ["CT","PT","Cb"]
    for j in range(0,len(term_names)):
        print("\\begin{align}")
        print("\\begin{split}")
        for i in range(1,1<<(len(expressions))):
            bits = "{0:b}".format(i)[::-1]
            o=0
            if (j==2):
                if i & 1:
                    continue
                o=-1
            bitcnt=0
            terms=[]

            for b in range(0,len(bits)):
                if bits[b]=='1':
                    bitcnt+=1
                    terms.append(b)

            tname = term_names[j]
            expr=""
            expr_val=None
            for term in terms:
                n="\%s_{%d}"%(tname,term+o)
                v=expressions[term][j]
                #print(n,": ",printer(v))
                expr+=n+" \oplus "
                if expr_val is None:
                    expr_val = v
                else:
                    expr_val = x.m(expr_val,v)
            if expr_val is not None:
                print(expr[:-8]," = ",printer(expr_val))
        if latex:
            print("\\end{split}")
            print("\\end{align}")




def cx2_symb(printer=latex_printer,verbose=True):
    print()
    latex = printer==latex_printer

    CT_0=var.m("\CT_0")
    PT_0=var.m("\PT_0")

    p_values = [None]

    depth = 5

    expressions = []
    for p in p_values:
        ct=CT_0
        pt=PT_0
        np=p
        #skip it since we want to xor the Ci
        expressions.append((ct,pt,p))
        for i in range(0,depth):
            (ct,pt,c) = spae_step(ct,pt,p)
            p=np
            np=c
            #print(i,": ",printer(p))
            expressions.append((ct,pt,c))

    print("$\Pb_i+1 = \Cb_{i-1}$, $\Pb_0=0$, $\Pb_1=0$")
    term_names = ["CT","PT","Cb"]
    for j in range(0,len(term_names)):
        print("\\begin{align}")
        print("\\begin{split}")
        for i in range(1,1<<(len(expressions))):
            bits = "{0:b}".format(i)[::-1]
            o=0
            if (j==2):
                if i & 1:
                    continue
                o=-1
            bitcnt=0
            terms=[]

            for b in range(0,len(bits)):
                if bits[b]=='1':
                    bitcnt+=1
                    terms.append(b)

            tname = term_names[j]
            expr=""
            expr_val=None
            for term in terms:
                n="\%s_{%d}"%(tname,term+o)
                v=expressions[term][j]
                #print(n,": ",printer(v))
                expr+=n+" \oplus "
                if expr_val is None:
                    expr_val = v
                else:
                    expr_val = x.m(expr_val,v)
            if expr_val is not None:
                print(expr[:-8]," = ",printer(expr_val))
        if latex:
            print("\\end{split}")
            print("\\end{align}")

















names={}

printer = latex_printer

if printer==latex_printer:
    names["k"]="\\Kb"
    names["ones"]="\\block{FF}"
else:
    names["k"]="k"
    names["ones"]="FF"

#test(v12g_init,v12h_null_tag,printer,verbose=False)
#cx(v12g_init,printer)
cx2_symb(printer)
