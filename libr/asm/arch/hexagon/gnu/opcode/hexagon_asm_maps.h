/*
 * Source Tag: A2_addsp
 * Source Syntax: Rdd32=add(Rs32,Rtt32)
 * Dest Syntax: Rdd32=add(Rss32,Rtt32):raw:hi
 * Dest Syntax2: Rdd32=add(Rss32,Rtt32):raw:lo
 * Condition: Rs32 & 1
 *
 */
MAP_FUNCTION(A2_addsp)
{
	if (GET_OP_VAL(1) & 1) {
		snprintf(i, n,"R%d:%d=add(R%d:%d,R%d:%d):raw:hi",GET_OP_VAL(0)+1,GET_OP_VAL(0),GET_OP_VAL(1) |1,GET_OP_VAL(1) & -2,GET_OP_VAL(2)+1,GET_OP_VAL(2));
	} else {
		snprintf(i, n,"R%d:%d=add(R%d:%d,R%d:%d):raw:lo",GET_OP_VAL(0)+1,GET_OP_VAL(0),GET_OP_VAL(1) |1,GET_OP_VAL(1) & -2,GET_OP_VAL(2)+1,GET_OP_VAL(2));
	}
}

/*
 * Source Tag: A2_neg
 * Source Syntax: Rd32=neg(Rs32)
 * Dest Syntax: Rd32=sub(#0,Rs32)
 *
 */
MAP_FUNCTION(A2_neg)
{
    snprintf(i, n,"R%d=sub(#0,R%d)",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: A2_not
 * Source Syntax: Rd32=not(Rs32)
 * Dest Syntax: Rd32=sub(#-1,Rs32)
 *
 */
MAP_FUNCTION(A2_not)
{
    snprintf(i, n,"R%d=sub(#-1,R%d)",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: A2_tfrf
 * Source Syntax: if (!Pu4) Rd32=Rs32
 * Dest Syntax: if (!Pu4) Rd32=add(Rs32,#0)
 *
 */
MAP_FUNCTION(A2_tfrf)
{
    snprintf(i, n,"if (!P%d) R%d=add(R%d,#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: A2_tfrf_alt
 * Source Syntax: if !Pu4 Rd32=Rs32
 * Dest Syntax: if (!Pu4) Rd32=add(Rs32,#0)
 *
 */
MAP_FUNCTION(A2_tfrf_alt)
{
    snprintf(i, n,"if (!P%d) R%d=add(R%d,#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: A2_tfrfnew
 * Source Syntax: if (!Pu4.new) Rd32=Rs32
 * Dest Syntax: if (!Pu4.new) Rd32=add(Rs32,#0)
 *
 */
MAP_FUNCTION(A2_tfrfnew)
{
    snprintf(i, n,"if (!P%d.new) R%d=add(R%d,#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: A2_tfrfnew_alt
 * Source Syntax: if !Pu4.new Rd32=Rs32
 * Dest Syntax: if (!Pu4.new) Rd32=add(Rs32,#0)
 *
 */
MAP_FUNCTION(A2_tfrfnew_alt)
{
    snprintf(i, n,"if (!P%d.new) R%d=add(R%d,#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: A2_tfrp
 * Source Syntax: Rdd32=Rss32
 * Dest Syntax: Rdd32=combine(Rss.H32,Rss.L32)
 *
 */
MAP_FUNCTION(A2_tfrp)
{
    snprintf(i, n,"R%d:%d=combine(R%d,R%d)",GET_OP_VAL(0)+1,GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1));
}

/*
 * Source Tag: A2_tfrpf
 * Source Syntax: if (!Pu4) Rdd32=Rss32
 * Dest Syntax: if (!Pu4) Rdd32=combine(Rss.H32,Rss.L32)
 *
 */
MAP_FUNCTION(A2_tfrpf)
{
    snprintf(i, n,"if (!P%d) R%d:%d=combine(R%d,R%d)",GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1),GET_OP_VAL(2)+1,GET_OP_VAL(2));
}

/*
 * Source Tag: A2_tfrpf_alt
 * Source Syntax: if !Pu4 Rdd32=Rss32
 * Dest Syntax: if (!Pu4) Rdd32=combine(Rss.H32,Rss.L32)
 *
 */
MAP_FUNCTION(A2_tfrpf_alt)
{
    snprintf(i, n,"if (!P%d) R%d:%d=combine(R%d,R%d)",GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1),GET_OP_VAL(2)+1,GET_OP_VAL(2));
}

/*
 * Source Tag: A2_tfrpfnew
 * Source Syntax: if (!Pu4.new) Rdd32=Rss32
 * Dest Syntax: if (!Pu4.new) Rdd32=combine(Rss.H32,Rss.L32)
 *
 */
MAP_FUNCTION(A2_tfrpfnew)
{
    snprintf(i, n,"if (!P%d.new) R%d:%d=combine(R%d,R%d)",GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1),GET_OP_VAL(2)+1,GET_OP_VAL(2));
}

/*
 * Source Tag: A2_tfrpfnew_alt
 * Source Syntax: if !Pu4.new Rdd32=Rss32
 * Dest Syntax: if (!Pu4.new) Rdd32=combine(Rss.H32,Rss.L32)
 *
 */
MAP_FUNCTION(A2_tfrpfnew_alt)
{
    snprintf(i, n,"if (!P%d.new) R%d:%d=combine(R%d,R%d)",GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1),GET_OP_VAL(2)+1,GET_OP_VAL(2));
}

/*
 * Source Tag: A2_tfrpi
 * Source Syntax: Rdd32=#s8
 * Dest Syntax: Rdd32=combine(#-1,#s8)
 * Dest Syntax2: Rdd32=combine(#0,#s8)
 * Condition: #s8<0
 *
 */
MAP_FUNCTION(A2_tfrpi)
{
	if (GET_OP_VAL(1)<0) {
		snprintf(i, n,"R%d:%d=combine(#-1,#%s)",GET_OP_VAL(0)+1,GET_OP_VAL(0),GET_OP_STR(1));
	} else {
		snprintf(i, n,"R%d:%d=combine(#0,#%s)",GET_OP_VAL(0)+1,GET_OP_VAL(0),GET_OP_STR(1));
	}
}

/*
 * Source Tag: A2_tfrpt
 * Source Syntax: if (Pu4) Rdd32=Rss32
 * Dest Syntax: if (Pu4) Rdd32=combine(Rss.H32,Rss.L32)
 *
 */
MAP_FUNCTION(A2_tfrpt)
{
    snprintf(i, n,"if (P%d) R%d:%d=combine(R%d,R%d)",GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1),GET_OP_VAL(2)+1,GET_OP_VAL(2));
}

/*
 * Source Tag: A2_tfrpt_alt
 * Source Syntax: if Pu4 Rdd32=Rss32
 * Dest Syntax: if (Pu4) Rdd32=combine(Rss.H32,Rss.L32)
 *
 */
MAP_FUNCTION(A2_tfrpt_alt)
{
    snprintf(i, n,"if (P%d) R%d:%d=combine(R%d,R%d)",GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1),GET_OP_VAL(2)+1,GET_OP_VAL(2));
}

/*
 * Source Tag: A2_tfrptnew
 * Source Syntax: if (Pu4.new) Rdd32=Rss32
 * Dest Syntax: if (Pu4.new) Rdd32=combine(Rss.H32,Rss.L32)
 *
 */
MAP_FUNCTION(A2_tfrptnew)
{
    snprintf(i, n,"if (P%d.new) R%d:%d=combine(R%d,R%d)",GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1),GET_OP_VAL(2)+1,GET_OP_VAL(2));
}

/*
 * Source Tag: A2_tfrptnew_alt
 * Source Syntax: if Pu4.new Rdd32=Rss32
 * Dest Syntax: if (Pu4.new) Rdd32=combine(Rss.H32,Rss.L32)
 *
 */
MAP_FUNCTION(A2_tfrptnew_alt)
{
    snprintf(i, n,"if (P%d.new) R%d:%d=combine(R%d,R%d)",GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1),GET_OP_VAL(2)+1,GET_OP_VAL(2));
}

/*
 * Source Tag: A2_tfrt
 * Source Syntax: if (Pu4) Rd32=Rs32
 * Dest Syntax: if (Pu4) Rd32=add(Rs32,#0)
 *
 */
MAP_FUNCTION(A2_tfrt)
{
    snprintf(i, n,"if (P%d) R%d=add(R%d,#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: A2_tfrt_alt
 * Source Syntax: if Pu4 Rd32=Rs32
 * Dest Syntax: if (Pu4) Rd32=add(Rs32,#0)
 *
 */
MAP_FUNCTION(A2_tfrt_alt)
{
    snprintf(i, n,"if (P%d) R%d=add(R%d,#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: A2_tfrtnew
 * Source Syntax: if (Pu4.new) Rd32=Rs32
 * Dest Syntax: if (Pu4.new) Rd32=add(Rs32,#0)
 *
 */
MAP_FUNCTION(A2_tfrtnew)
{
    snprintf(i, n,"if (P%d.new) R%d=add(R%d,#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: A2_tfrtnew_alt
 * Source Syntax: if Pu4.new Rd32=Rs32
 * Dest Syntax: if (Pu4.new) Rd32=add(Rs32,#0)
 *
 */
MAP_FUNCTION(A2_tfrtnew_alt)
{
    snprintf(i, n,"if (P%d.new) R%d=add(R%d,#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: A2_vaddb_map
 * Source Syntax: Rdd32=vaddb(Rss32,Rtt32)
 * Dest Syntax: Rdd32=vaddub(Rss32,Rtt32)
 *
 */
MAP_FUNCTION(A2_vaddb_map)
{
    snprintf(i, n,"R%d:%d=vaddub(R%d:%d,R%d:%d)",GET_OP_VAL(0)+1,GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1),GET_OP_VAL(2)+1,GET_OP_VAL(2));
}

/*
 * Source Tag: A2_vsubb_map
 * Source Syntax: Rdd32=vsubb(Rss32,Rtt32)
 * Dest Syntax: Rdd32=vsubub(Rss32,Rtt32)
 *
 */
MAP_FUNCTION(A2_vsubb_map)
{
    snprintf(i, n,"R%d:%d=vsubub(R%d:%d,R%d:%d)",GET_OP_VAL(0)+1,GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1),GET_OP_VAL(2)+1,GET_OP_VAL(2));
}

/*
 * Source Tag: A2_zxtb
 * Source Syntax: Rd32=zxtb(Rs32)
 * Dest Syntax: Rd32=and(Rs32,#255)
 *
 */
MAP_FUNCTION(A2_zxtb)
{
    snprintf(i, n,"R%d=and(R%d,#255)",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: A4_boundscheck
 * Source Syntax: Pd4=boundscheck(Rs32,Rtt32)
 * Dest Syntax: Pd4=boundscheck(Rss32,Rtt32):raw:hi
 * Dest Syntax2: Pd4=boundscheck(Rss32,Rtt32):raw:lo
 * Condition: Rs32 & 1
 *
 */
MAP_FUNCTION(A4_boundscheck)
{
	if (GET_OP_VAL(1) & 1) {
		snprintf(i, n,"P%d=boundscheck(R%d:%d,R%d:%d):raw:hi",GET_OP_VAL(0),GET_OP_VAL(1) |1,GET_OP_VAL(1) & -2,GET_OP_VAL(2)+1,GET_OP_VAL(2));
	} else {
		snprintf(i, n,"P%d=boundscheck(R%d:%d,R%d:%d):raw:lo",GET_OP_VAL(0),GET_OP_VAL(1) |1,GET_OP_VAL(1) & -2,GET_OP_VAL(2)+1,GET_OP_VAL(2));
	}
}

/*
 * Source Tag: C2_cmpgei
 * Source Syntax: Pd4=cmp.ge(Rs32,#s8)
 * Dest Syntax: Pd4=cmp.gt(Rs32,#s8-1)
 *
 */
MAP_FUNCTION(C2_cmpgei)
{
    snprintf(i, n,"P%d=cmp.gt(R%d,#%s-1)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
}

/*
 * Source Tag: C2_cmpgeui
 * Source Syntax: Pd4=cmp.geu(Rs32,#u8)
 * Dest Syntax: Pd4=cmp.eq(Rs32,Rs32)
 * Dest Syntax2: Pd4=cmp.gtu(Rs32,#u8-1)
 * Condition: #u8==0
 *
 */
MAP_FUNCTION(C2_cmpgeui)
{
	if (GET_OP_VAL(2)==0) {
		snprintf(i, n,"P%d=cmp.eq(R%d,R%d)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(1));
	} else {
		snprintf(i, n,"P%d=cmp.gtu(R%d,#%s-1)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
	}
}

/*
 * Source Tag: C2_cmplt
 * Source Syntax: Pd4=cmp.lt(Rs32,Rt32)
 * Dest Syntax: Pd4=cmp.gt(Rt32,Rs32)
 *
 */
MAP_FUNCTION(C2_cmplt)
{
    snprintf(i, n,"P%d=cmp.gt(R%d,R%d)",GET_OP_VAL(0),GET_OP_VAL(2),GET_OP_VAL(1));
}

/*
 * Source Tag: C2_cmpltu
 * Source Syntax: Pd4=cmp.ltu(Rs32,Rt32)
 * Dest Syntax: Pd4=cmp.gtu(Rt32,Rs32)
 *
 */
MAP_FUNCTION(C2_cmpltu)
{
    snprintf(i, n,"P%d=cmp.gtu(R%d,R%d)",GET_OP_VAL(0),GET_OP_VAL(2),GET_OP_VAL(1));
}

/*
 * Source Tag: C2_pxfer_map
 * Source Syntax: Pd4=Ps4
 * Dest Syntax: Pd4=or(Ps4,Ps4)
 *
 */
MAP_FUNCTION(C2_pxfer_map)
{
    snprintf(i, n,"P%d=or(P%d,P%d)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(1));
}

/*
 * Source Tag: L2_loadalignb_zomap
 * Source Syntax: Ryy32=memb_fifo(Rs32)
 * Dest Syntax: Ryy32=memb_fifo(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_loadalignb_zomap)
{
    snprintf(i, n,"R%d:%d=memb_fifo(R%d+#0)",GET_OP_VAL(0)+1,GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: L2_loadalignh_zomap
 * Source Syntax: Ryy32=memh_fifo(Rs32)
 * Dest Syntax: Ryy32=memh_fifo(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_loadalignh_zomap)
{
    snprintf(i, n,"R%d:%d=memh_fifo(R%d+#0)",GET_OP_VAL(0)+1,GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: L2_loadbsw2_zomap
 * Source Syntax: Rd32=membh(Rs32)
 * Dest Syntax: Rd32=membh(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_loadbsw2_zomap)
{
    snprintf(i, n,"R%d=membh(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: L2_loadbsw4_zomap
 * Source Syntax: Rdd32=membh(Rs32)
 * Dest Syntax: Rdd32=membh(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_loadbsw4_zomap)
{
    snprintf(i, n,"R%d:%d=membh(R%d+#0)",GET_OP_VAL(0)+1,GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: L2_loadbzw2_zomap
 * Source Syntax: Rd32=memubh(Rs32)
 * Dest Syntax: Rd32=memubh(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_loadbzw2_zomap)
{
    snprintf(i, n,"R%d=memubh(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: L2_loadbzw4_zomap
 * Source Syntax: Rdd32=memubh(Rs32)
 * Dest Syntax: Rdd32=memubh(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_loadbzw4_zomap)
{
    snprintf(i, n,"R%d:%d=memubh(R%d+#0)",GET_OP_VAL(0)+1,GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: L2_loadrb_zomap
 * Source Syntax: Rd32=memb(Rs32)
 * Dest Syntax: Rd32=memb(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_loadrb_zomap)
{
    snprintf(i, n,"R%d=memb(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: L2_loadrd_zomap
 * Source Syntax: Rdd32=memd(Rs32)
 * Dest Syntax: Rdd32=memd(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_loadrd_zomap)
{
    snprintf(i, n,"R%d:%d=memd(R%d+#0)",GET_OP_VAL(0)+1,GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: L2_loadrh_zomap
 * Source Syntax: Rd32=memh(Rs32)
 * Dest Syntax: Rd32=memh(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_loadrh_zomap)
{
    snprintf(i, n,"R%d=memh(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: L2_loadri_zomap
 * Source Syntax: Rd32=memw(Rs32)
 * Dest Syntax: Rd32=memw(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_loadri_zomap)
{
    snprintf(i, n,"R%d=memw(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: L2_loadrub_zomap
 * Source Syntax: Rd32=memub(Rs32)
 * Dest Syntax: Rd32=memub(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_loadrub_zomap)
{
    snprintf(i, n,"R%d=memub(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: L2_loadruh_zomap
 * Source Syntax: Rd32=memuh(Rs32)
 * Dest Syntax: Rd32=memuh(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_loadruh_zomap)
{
    snprintf(i, n,"R%d=memuh(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: L2_ploadrbf_zomap
 * Source Syntax: if (!Pt4) Rd32=memb(Rs32)
 * Dest Syntax: if (!Pt4) Rd32=memb(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrbf_zomap)
{
    snprintf(i, n,"if (!P%d) R%d=memb(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrbf_zomap_alt
 * Source Syntax: if !Pt4 Rd32=memb(Rs32)
 * Dest Syntax: if (!Pt4) Rd32=memb(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrbf_zomap_alt)
{
    snprintf(i, n,"if (!P%d) R%d=memb(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrbfnew_zomap
 * Source Syntax: if (!Pt4.new) Rd32=memb(Rs32)
 * Dest Syntax: if (!Pt4.new) Rd32=memb(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrbfnew_zomap)
{
    snprintf(i, n,"if (!P%d.new) R%d=memb(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrbfnew_zomap_alt
 * Source Syntax: if !Pt4.new Rd32=memb(Rs32)
 * Dest Syntax: if (!Pt4.new) Rd32=memb(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrbfnew_zomap_alt)
{
    snprintf(i, n,"if (!P%d.new) R%d=memb(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrbt_zomap
 * Source Syntax: if (Pt4) Rd32=memb(Rs32)
 * Dest Syntax: if (Pt4) Rd32=memb(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrbt_zomap)
{
    snprintf(i, n,"if (P%d) R%d=memb(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrbt_zomap_alt
 * Source Syntax: if Pt4 Rd32=memb(Rs32)
 * Dest Syntax: if (Pt4) Rd32=memb(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrbt_zomap_alt)
{
    snprintf(i, n,"if (P%d) R%d=memb(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrbtnew_zomap
 * Source Syntax: if (Pt4.new) Rd32=memb(Rs32)
 * Dest Syntax: if (Pt4.new) Rd32=memb(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrbtnew_zomap)
{
    snprintf(i, n,"if (P%d.new) R%d=memb(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrbtnew_zomap_alt
 * Source Syntax: if Pt4.new Rd32=memb(Rs32)
 * Dest Syntax: if (Pt4.new) Rd32=memb(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrbtnew_zomap_alt)
{
    snprintf(i, n,"if (P%d.new) R%d=memb(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrdf_zomap
 * Source Syntax: if (!Pt4) Rdd32=memd(Rs32)
 * Dest Syntax: if (!Pt4) Rdd32=memd(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrdf_zomap)
{
    snprintf(i, n,"if (!P%d) R%d:%d=memd(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrdf_zomap_alt
 * Source Syntax: if !Pt4 Rdd32=memd(Rs32)
 * Dest Syntax: if (!Pt4) Rdd32=memd(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrdf_zomap_alt)
{
    snprintf(i, n,"if (!P%d) R%d:%d=memd(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrdfnew_zomap
 * Source Syntax: if (!Pt4.new) Rdd32=memd(Rs32)
 * Dest Syntax: if (!Pt4.new) Rdd32=memd(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrdfnew_zomap)
{
    snprintf(i, n,"if (!P%d.new) R%d:%d=memd(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrdfnew_zomap_alt
 * Source Syntax: if !Pt4.new Rdd32=memd(Rs32)
 * Dest Syntax: if (!Pt4.new) Rdd32=memd(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrdfnew_zomap_alt)
{
    snprintf(i, n,"if (!P%d.new) R%d:%d=memd(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrdt_zomap
 * Source Syntax: if (Pt4) Rdd32=memd(Rs32)
 * Dest Syntax: if (Pt4) Rdd32=memd(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrdt_zomap)
{
    snprintf(i, n,"if (P%d) R%d:%d=memd(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrdt_zomap_alt
 * Source Syntax: if Pt4 Rdd32=memd(Rs32)
 * Dest Syntax: if (Pt4) Rdd32=memd(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrdt_zomap_alt)
{
    snprintf(i, n,"if (P%d) R%d:%d=memd(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrdtnew_zomap
 * Source Syntax: if (Pt4.new) Rdd32=memd(Rs32)
 * Dest Syntax: if (Pt4.new) Rdd32=memd(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrdtnew_zomap)
{
    snprintf(i, n,"if (P%d.new) R%d:%d=memd(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrdtnew_zomap_alt
 * Source Syntax: if Pt4.new Rdd32=memd(Rs32)
 * Dest Syntax: if (Pt4.new) Rdd32=memd(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrdtnew_zomap_alt)
{
    snprintf(i, n,"if (P%d.new) R%d:%d=memd(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrhf_zomap
 * Source Syntax: if (!Pt4) Rd32=memh(Rs32)
 * Dest Syntax: if (!Pt4) Rd32=memh(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrhf_zomap)
{
    snprintf(i, n,"if (!P%d) R%d=memh(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrhf_zomap_alt
 * Source Syntax: if !Pt4 Rd32=memh(Rs32)
 * Dest Syntax: if (!Pt4) Rd32=memh(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrhf_zomap_alt)
{
    snprintf(i, n,"if (!P%d) R%d=memh(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrhfnew_zomap
 * Source Syntax: if (!Pt4.new) Rd32=memh(Rs32)
 * Dest Syntax: if (!Pt4.new) Rd32=memh(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrhfnew_zomap)
{
    snprintf(i, n,"if (!P%d.new) R%d=memh(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrhfnew_zomap_alt
 * Source Syntax: if !Pt4.new Rd32=memh(Rs32)
 * Dest Syntax: if (!Pt4.new) Rd32=memh(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrhfnew_zomap_alt)
{
    snprintf(i, n,"if (!P%d.new) R%d=memh(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrht_zomap
 * Source Syntax: if (Pt4) Rd32=memh(Rs32)
 * Dest Syntax: if (Pt4) Rd32=memh(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrht_zomap)
{
    snprintf(i, n,"if (P%d) R%d=memh(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrht_zomap_alt
 * Source Syntax: if Pt4 Rd32=memh(Rs32)
 * Dest Syntax: if (Pt4) Rd32=memh(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrht_zomap_alt)
{
    snprintf(i, n,"if (P%d) R%d=memh(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrhtnew_zomap
 * Source Syntax: if (Pt4.new) Rd32=memh(Rs32)
 * Dest Syntax: if (Pt4.new) Rd32=memh(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrhtnew_zomap)
{
    snprintf(i, n,"if (P%d.new) R%d=memh(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrhtnew_zomap_alt
 * Source Syntax: if Pt4.new Rd32=memh(Rs32)
 * Dest Syntax: if (Pt4.new) Rd32=memh(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrhtnew_zomap_alt)
{
    snprintf(i, n,"if (P%d.new) R%d=memh(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrif_zomap
 * Source Syntax: if (!Pt4) Rd32=memw(Rs32)
 * Dest Syntax: if (!Pt4) Rd32=memw(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrif_zomap)
{
    snprintf(i, n,"if (!P%d) R%d=memw(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrif_zomap_alt
 * Source Syntax: if !Pt4 Rd32=memw(Rs32)
 * Dest Syntax: if (!Pt4) Rd32=memw(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrif_zomap_alt)
{
    snprintf(i, n,"if (!P%d) R%d=memw(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrifnew_zomap
 * Source Syntax: if (!Pt4.new) Rd32=memw(Rs32)
 * Dest Syntax: if (!Pt4.new) Rd32=memw(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrifnew_zomap)
{
    snprintf(i, n,"if (!P%d.new) R%d=memw(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrifnew_zomap_alt
 * Source Syntax: if !Pt4.new Rd32=memw(Rs32)
 * Dest Syntax: if (!Pt4.new) Rd32=memw(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrifnew_zomap_alt)
{
    snprintf(i, n,"if (!P%d.new) R%d=memw(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrit_zomap
 * Source Syntax: if (Pt4) Rd32=memw(Rs32)
 * Dest Syntax: if (Pt4) Rd32=memw(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrit_zomap)
{
    snprintf(i, n,"if (P%d) R%d=memw(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrit_zomap_alt
 * Source Syntax: if Pt4 Rd32=memw(Rs32)
 * Dest Syntax: if (Pt4) Rd32=memw(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrit_zomap_alt)
{
    snprintf(i, n,"if (P%d) R%d=memw(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadritnew_zomap
 * Source Syntax: if (Pt4.new) Rd32=memw(Rs32)
 * Dest Syntax: if (Pt4.new) Rd32=memw(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadritnew_zomap)
{
    snprintf(i, n,"if (P%d.new) R%d=memw(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadritnew_zomap_alt
 * Source Syntax: if Pt4.new Rd32=memw(Rs32)
 * Dest Syntax: if (Pt4.new) Rd32=memw(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadritnew_zomap_alt)
{
    snprintf(i, n,"if (P%d.new) R%d=memw(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrubf_zomap
 * Source Syntax: if (!Pt4) Rd32=memub(Rs32)
 * Dest Syntax: if (!Pt4) Rd32=memub(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrubf_zomap)
{
    snprintf(i, n,"if (!P%d) R%d=memub(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrubf_zomap_alt
 * Source Syntax: if !Pt4 Rd32=memub(Rs32)
 * Dest Syntax: if (!Pt4) Rd32=memub(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrubf_zomap_alt)
{
    snprintf(i, n,"if (!P%d) R%d=memub(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrubfnew_zomap
 * Source Syntax: if (!Pt4.new) Rd32=memub(Rs32)
 * Dest Syntax: if (!Pt4.new) Rd32=memub(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrubfnew_zomap)
{
    snprintf(i, n,"if (!P%d.new) R%d=memub(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrubfnew_zomap_alt
 * Source Syntax: if !Pt4.new Rd32=memub(Rs32)
 * Dest Syntax: if (!Pt4.new) Rd32=memub(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrubfnew_zomap_alt)
{
    snprintf(i, n,"if (!P%d.new) R%d=memub(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrubt_zomap
 * Source Syntax: if (Pt4) Rd32=memub(Rs32)
 * Dest Syntax: if (Pt4) Rd32=memub(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrubt_zomap)
{
    snprintf(i, n,"if (P%d) R%d=memub(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrubt_zomap_alt
 * Source Syntax: if Pt4 Rd32=memub(Rs32)
 * Dest Syntax: if (Pt4) Rd32=memub(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrubt_zomap_alt)
{
    snprintf(i, n,"if (P%d) R%d=memub(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrubtnew_zomap
 * Source Syntax: if (Pt4.new) Rd32=memub(Rs32)
 * Dest Syntax: if (Pt4.new) Rd32=memub(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrubtnew_zomap)
{
    snprintf(i, n,"if (P%d.new) R%d=memub(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadrubtnew_zomap_alt
 * Source Syntax: if Pt4.new Rd32=memub(Rs32)
 * Dest Syntax: if (Pt4.new) Rd32=memub(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadrubtnew_zomap_alt)
{
    snprintf(i, n,"if (P%d.new) R%d=memub(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadruhf_zomap
 * Source Syntax: if (!Pt4) Rd32=memuh(Rs32)
 * Dest Syntax: if (!Pt4) Rd32=memuh(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadruhf_zomap)
{
    snprintf(i, n,"if (!P%d) R%d=memuh(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadruhf_zomap_alt
 * Source Syntax: if !Pt4 Rd32=memuh(Rs32)
 * Dest Syntax: if (!Pt4) Rd32=memuh(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadruhf_zomap_alt)
{
    snprintf(i, n,"if (!P%d) R%d=memuh(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadruhfnew_zomap
 * Source Syntax: if (!Pt4.new) Rd32=memuh(Rs32)
 * Dest Syntax: if (!Pt4.new) Rd32=memuh(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadruhfnew_zomap)
{
    snprintf(i, n,"if (!P%d.new) R%d=memuh(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadruhfnew_zomap_alt
 * Source Syntax: if !Pt4.new Rd32=memuh(Rs32)
 * Dest Syntax: if (!Pt4.new) Rd32=memuh(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadruhfnew_zomap_alt)
{
    snprintf(i, n,"if (!P%d.new) R%d=memuh(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadruht_zomap
 * Source Syntax: if (Pt4) Rd32=memuh(Rs32)
 * Dest Syntax: if (Pt4) Rd32=memuh(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadruht_zomap)
{
    snprintf(i, n,"if (P%d) R%d=memuh(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadruht_zomap_alt
 * Source Syntax: if Pt4 Rd32=memuh(Rs32)
 * Dest Syntax: if (Pt4) Rd32=memuh(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadruht_zomap_alt)
{
    snprintf(i, n,"if (P%d) R%d=memuh(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadruhtnew_zomap
 * Source Syntax: if (Pt4.new) Rd32=memuh(Rs32)
 * Dest Syntax: if (Pt4.new) Rd32=memuh(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadruhtnew_zomap)
{
    snprintf(i, n,"if (P%d.new) R%d=memuh(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L2_ploadruhtnew_zomap_alt
 * Source Syntax: if Pt4.new Rd32=memuh(Rs32)
 * Dest Syntax: if (Pt4.new) Rd32=memuh(Rs32+#0)
 *
 */
MAP_FUNCTION(L2_ploadruhtnew_zomap_alt)
{
    snprintf(i, n,"if (P%d.new) R%d=memuh(R%d+#0)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: L4_add_memopb_zomap
 * Source Syntax: memb(Rs32)+=Rt32
 * Dest Syntax: memb(Rs32+#0)+=Rt32
 *
 */
MAP_FUNCTION(L4_add_memopb_zomap)
{
    snprintf(i, n,"memb(R%d+#0)+=R%d",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: L4_add_memoph_zomap
 * Source Syntax: memh(Rs32)+=Rt32
 * Dest Syntax: memh(Rs32+#0)+=Rt32
 *
 */
MAP_FUNCTION(L4_add_memoph_zomap)
{
    snprintf(i, n,"memh(R%d+#0)+=R%d",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: L4_add_memopw_zomap
 * Source Syntax: memw(Rs32)+=Rt32
 * Dest Syntax: memw(Rs32+#0)+=Rt32
 *
 */
MAP_FUNCTION(L4_add_memopw_zomap)
{
    snprintf(i, n,"memw(R%d+#0)+=R%d",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: L4_and_memopb_zomap
 * Source Syntax: memb(Rs32)&=Rt32
 * Dest Syntax: memb(Rs32+#0)&=Rt32
 *
 */
MAP_FUNCTION(L4_and_memopb_zomap)
{
    snprintf(i, n,"memb(R%d+#0)&=R%d",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: L4_and_memoph_zomap
 * Source Syntax: memh(Rs32)&=Rt32
 * Dest Syntax: memh(Rs32+#0)&=Rt32
 *
 */
MAP_FUNCTION(L4_and_memoph_zomap)
{
    snprintf(i, n,"memh(R%d+#0)&=R%d",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: L4_and_memopw_zomap
 * Source Syntax: memw(Rs32)&=Rt32
 * Dest Syntax: memw(Rs32+#0)&=Rt32
 *
 */
MAP_FUNCTION(L4_and_memopw_zomap)
{
    snprintf(i, n,"memw(R%d+#0)&=R%d",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: L4_iadd_memopb_zomap
 * Source Syntax: memb(Rs32)+=#U5
 * Dest Syntax: memb(Rs32+#0)+=#U5
 *
 */
MAP_FUNCTION(L4_iadd_memopb_zomap)
{
    snprintf(i, n,"memb(R%d+#0)+=#%s",GET_OP_VAL(0),GET_OP_STR(1));
}

/*
 * Source Tag: L4_iadd_memoph_zomap
 * Source Syntax: memh(Rs32)+=#U5
 * Dest Syntax: memh(Rs32+#0)+=#U5
 *
 */
MAP_FUNCTION(L4_iadd_memoph_zomap)
{
    snprintf(i, n,"memh(R%d+#0)+=#%s",GET_OP_VAL(0),GET_OP_STR(1));
}

/*
 * Source Tag: L4_iadd_memopw_zomap
 * Source Syntax: memw(Rs32)+=#U5
 * Dest Syntax: memw(Rs32+#0)+=#U5
 *
 */
MAP_FUNCTION(L4_iadd_memopw_zomap)
{
    snprintf(i, n,"memw(R%d+#0)+=#%s",GET_OP_VAL(0),GET_OP_STR(1));
}

/*
 * Source Tag: L4_iand_memopb_zomap
 * Source Syntax: memb(Rs32)=clrbit(#U5)
 * Dest Syntax: memb(Rs32+#0)=clrbit(#U5)
 *
 */
MAP_FUNCTION(L4_iand_memopb_zomap)
{
    snprintf(i, n,"memb(R%d+#0)=clrbit(#%s)",GET_OP_VAL(0),GET_OP_STR(1));
}

/*
 * Source Tag: L4_iand_memoph_zomap
 * Source Syntax: memh(Rs32)=clrbit(#U5)
 * Dest Syntax: memh(Rs32+#0)=clrbit(#U5)
 *
 */
MAP_FUNCTION(L4_iand_memoph_zomap)
{
    snprintf(i, n,"memh(R%d+#0)=clrbit(#%s)",GET_OP_VAL(0),GET_OP_STR(1));
}

/*
 * Source Tag: L4_iand_memopw_zomap
 * Source Syntax: memw(Rs32)=clrbit(#U5)
 * Dest Syntax: memw(Rs32+#0)=clrbit(#U5)
 *
 */
MAP_FUNCTION(L4_iand_memopw_zomap)
{
    snprintf(i, n,"memw(R%d+#0)=clrbit(#%s)",GET_OP_VAL(0),GET_OP_STR(1));
}

/*
 * Source Tag: L4_ior_memopb_zomap
 * Source Syntax: memb(Rs32)=setbit(#U5)
 * Dest Syntax: memb(Rs32+#0)=setbit(#U5)
 *
 */
MAP_FUNCTION(L4_ior_memopb_zomap)
{
    snprintf(i, n,"memb(R%d+#0)=setbit(#%s)",GET_OP_VAL(0),GET_OP_STR(1));
}

/*
 * Source Tag: L4_ior_memoph_zomap
 * Source Syntax: memh(Rs32)=setbit(#U5)
 * Dest Syntax: memh(Rs32+#0)=setbit(#U5)
 *
 */
MAP_FUNCTION(L4_ior_memoph_zomap)
{
    snprintf(i, n,"memh(R%d+#0)=setbit(#%s)",GET_OP_VAL(0),GET_OP_STR(1));
}

/*
 * Source Tag: L4_ior_memopw_zomap
 * Source Syntax: memw(Rs32)=setbit(#U5)
 * Dest Syntax: memw(Rs32+#0)=setbit(#U5)
 *
 */
MAP_FUNCTION(L4_ior_memopw_zomap)
{
    snprintf(i, n,"memw(R%d+#0)=setbit(#%s)",GET_OP_VAL(0),GET_OP_STR(1));
}

/*
 * Source Tag: L4_isub_memopb_zomap
 * Source Syntax: memb(Rs32)-=#U5
 * Dest Syntax: memb(Rs32+#0)-=#U5
 *
 */
MAP_FUNCTION(L4_isub_memopb_zomap)
{
    snprintf(i, n,"memb(R%d+#0)-=#%s",GET_OP_VAL(0),GET_OP_STR(1));
}

/*
 * Source Tag: L4_isub_memoph_zomap
 * Source Syntax: memh(Rs32)-=#U5
 * Dest Syntax: memh(Rs32+#0)-=#U5
 *
 */
MAP_FUNCTION(L4_isub_memoph_zomap)
{
    snprintf(i, n,"memh(R%d+#0)-=#%s",GET_OP_VAL(0),GET_OP_STR(1));
}

/*
 * Source Tag: L4_isub_memopw_zomap
 * Source Syntax: memw(Rs32)-=#U5
 * Dest Syntax: memw(Rs32+#0)-=#U5
 *
 */
MAP_FUNCTION(L4_isub_memopw_zomap)
{
    snprintf(i, n,"memw(R%d+#0)-=#%s",GET_OP_VAL(0),GET_OP_STR(1));
}

/*
 * Source Tag: L4_or_memopb_zomap
 * Source Syntax: memb(Rs32)|=Rt32
 * Dest Syntax: memb(Rs32+#0)|=Rt32
 *
 */
MAP_FUNCTION(L4_or_memopb_zomap)
{
    snprintf(i, n,"memb(R%d+#0)|=R%d",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: L4_or_memoph_zomap
 * Source Syntax: memh(Rs32)|=Rt32
 * Dest Syntax: memh(Rs32+#0)|=Rt32
 *
 */
MAP_FUNCTION(L4_or_memoph_zomap)
{
    snprintf(i, n,"memh(R%d+#0)|=R%d",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: L4_or_memopw_zomap
 * Source Syntax: memw(Rs32)|=Rt32
 * Dest Syntax: memw(Rs32+#0)|=Rt32
 *
 */
MAP_FUNCTION(L4_or_memopw_zomap)
{
    snprintf(i, n,"memw(R%d+#0)|=R%d",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: L4_sub_memopb_zomap
 * Source Syntax: memb(Rs32)-=Rt32
 * Dest Syntax: memb(Rs32+#0)-=Rt32
 *
 */
MAP_FUNCTION(L4_sub_memopb_zomap)
{
    snprintf(i, n,"memb(R%d+#0)-=R%d",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: L4_sub_memoph_zomap
 * Source Syntax: memh(Rs32)-=Rt32
 * Dest Syntax: memh(Rs32+#0)-=Rt32
 *
 */
MAP_FUNCTION(L4_sub_memoph_zomap)
{
    snprintf(i, n,"memh(R%d+#0)-=R%d",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: L4_sub_memopw_zomap
 * Source Syntax: memw(Rs32)-=Rt32
 * Dest Syntax: memw(Rs32+#0)-=Rt32
 *
 */
MAP_FUNCTION(L4_sub_memopw_zomap)
{
    snprintf(i, n,"memw(R%d+#0)-=R%d",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: M2_mpysmi
 * Source Syntax: Rd32=mpyi(Rs32,#m9)
 * Dest Syntax: Rd32=-mpyi(Rs32,#m9*(-1))
 * Dest Syntax2: Rd32=+mpyi(Rs32,#m9)
 * Condition: ((#m9<0) && (#m9>-256))
 *
 */
MAP_FUNCTION(M2_mpysmi)
{
	if (((GET_OP_VAL(2)<0) && (GET_OP_VAL(2)>-256))) {
		snprintf(i, n,"R%d=-mpyi(R%d,#%s*(-1))",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
	} else {
		snprintf(i, n,"R%d=+mpyi(R%d,#%s)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
	}
}

/*
 * Source Tag: M2_mpyui
 * Source Syntax: Rd32=mpyui(Rs32,Rt32)
 * Dest Syntax: Rd32=mpyi(Rs32,Rt32)
 *
 */
MAP_FUNCTION(M2_mpyui)
{
    snprintf(i, n,"R%d=mpyi(R%d,R%d)",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: M2_vrcmpys_acc_s1
 * Source Syntax: Rxx32+=vrcmpys(Rss32,Rt32):<<1:sat
 * Dest Syntax: Rxx32+=vrcmpys(Rss32,Rtt32):<<1:sat:raw:hi
 * Dest Syntax2: Rxx32+=vrcmpys(Rss32,Rtt32):<<1:sat:raw:lo
 * Condition: Rt32 & 1
 *
 */
MAP_FUNCTION(M2_vrcmpys_acc_s1)
{
	if (GET_OP_VAL(2) & 1) {
		snprintf(i, n,"R%d:%d+=vrcmpys(R%d:%d,R%d:%d):<<1:sat:raw:hi",GET_OP_VAL(0)+1,GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1),GET_OP_VAL(2) |1,GET_OP_VAL(2) & -2);
	} else {
		snprintf(i, n,"R%d:%d+=vrcmpys(R%d:%d,R%d:%d):<<1:sat:raw:lo",GET_OP_VAL(0)+1,GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1),GET_OP_VAL(2) |1,GET_OP_VAL(2) & -2);
	}
}

/*
 * Source Tag: M2_vrcmpys_s1
 * Source Syntax: Rdd32=vrcmpys(Rss32,Rt32):<<1:sat
 * Dest Syntax: Rdd32=vrcmpys(Rss32,Rtt32):<<1:sat:raw:hi
 * Dest Syntax2: Rdd32=vrcmpys(Rss32,Rtt32):<<1:sat:raw:lo
 * Condition: Rt32 & 1
 *
 */
MAP_FUNCTION(M2_vrcmpys_s1)
{
	if (GET_OP_VAL(2) & 1) {
		snprintf(i, n,"R%d:%d=vrcmpys(R%d:%d,R%d:%d):<<1:sat:raw:hi",GET_OP_VAL(0)+1,GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1),GET_OP_VAL(2) |1,GET_OP_VAL(2) & -2);
	} else {
		snprintf(i, n,"R%d:%d=vrcmpys(R%d:%d,R%d:%d):<<1:sat:raw:lo",GET_OP_VAL(0)+1,GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1),GET_OP_VAL(2) |1,GET_OP_VAL(2) & -2);
	}
}

/*
 * Source Tag: M2_vrcmpys_s1rp
 * Source Syntax: Rd32=vrcmpys(Rss32,Rt32):<<1:rnd:sat
 * Dest Syntax: Rd32=vrcmpys(Rss32,Rtt32):<<1:rnd:sat:raw:hi
 * Dest Syntax2: Rd32=vrcmpys(Rss32,Rtt32):<<1:rnd:sat:raw:lo
 * Condition: Rt32 & 1
 *
 */
MAP_FUNCTION(M2_vrcmpys_s1rp)
{
	if (GET_OP_VAL(2) & 1) {
		snprintf(i, n,"R%d=vrcmpys(R%d:%d,R%d:%d):<<1:rnd:sat:raw:hi",GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1),GET_OP_VAL(2) |1,GET_OP_VAL(2) & -2);
	} else {
		snprintf(i, n,"R%d=vrcmpys(R%d:%d,R%d:%d):<<1:rnd:sat:raw:lo",GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1),GET_OP_VAL(2) |1,GET_OP_VAL(2) & -2);
	}
}

/*
 * Source Tag: S2_asr_i_p_rnd_goodsyntax
 * Source Syntax: Rdd32=asrrnd(Rss32,#u6)
 * Dest Syntax: Rdd32=Rss32
 * Dest Syntax2: Rdd32=asr(Rss32,#u5-1):rnd
 * Condition: #u6==0
 *
 */
MAP_FUNCTION(S2_asr_i_p_rnd_goodsyntax)
{
	if (GET_OP_VAL(2)==0) {
		snprintf(i, n,"R%d:%d=R%d:%d",GET_OP_VAL(0)+1,GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1));
	} else {
		snprintf(i, n,"R%d:%d=asr(R%d:%d,#u5-1):rnd",GET_OP_VAL(0)+1,GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1));
	}
}

/*
 * Source Tag: S2_asr_i_r_rnd_goodsyntax
 * Source Syntax: Rd32=asrrnd(Rs32,#u5)
 * Dest Syntax: Rd32=Rs32
 * Dest Syntax2: Rd32=asr(Rs32,#u5-1):rnd
 * Condition: #u5==0
 *
 */
MAP_FUNCTION(S2_asr_i_r_rnd_goodsyntax)
{
	if (GET_OP_VAL(2)==0) {
		snprintf(i, n,"R%d=R%d",GET_OP_VAL(0),GET_OP_VAL(1));
	} else {
		snprintf(i, n,"R%d=asr(R%d,#%s-1):rnd",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
	}
}

/*
 * Source Tag: S2_pstorerbf_zomap
 * Source Syntax: if (!Pv4) memb(Rs32)=Rt32
 * Dest Syntax: if (!Pv4) memb(Rs32+#0)=Rt32
 *
 */
MAP_FUNCTION(S2_pstorerbf_zomap)
{
    snprintf(i, n,"if (!P%d) memb(R%d+#0)=R%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerbf_zomap_alt
 * Source Syntax: if !Pv4 memb(Rs32)=Rt32
 * Dest Syntax: if (!Pv4) memb(Rs32+#0)=Rt32
 *
 */
MAP_FUNCTION(S2_pstorerbf_zomap_alt)
{
    snprintf(i, n,"if (!P%d) memb(R%d+#0)=R%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerbnewf_zomap
 * Source Syntax: if (!Pv4) memb(Rs32)=Nt8.new
 * Dest Syntax: if (!Pv4) memb(Rs32+#0)=Nt8.new
 *
 */
MAP_FUNCTION(S2_pstorerbnewf_zomap)
{
    snprintf(i, n,"if (!P%d) memb(R%d+#0)=R%d.new",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerbnewf_zomap_alt
 * Source Syntax: if !Pv4 memb(Rs32)=Nt8.new
 * Dest Syntax: if (!Pv4) memb(Rs32+#0)=Nt8.new
 *
 */
MAP_FUNCTION(S2_pstorerbnewf_zomap_alt)
{
    snprintf(i, n,"if (!P%d) memb(R%d+#0)=R%d.new",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerbnewt_zomap
 * Source Syntax: if (Pv4) memb(Rs32)=Nt8.new
 * Dest Syntax: if (Pv4) memb(Rs32+#0)=Nt8.new
 *
 */
MAP_FUNCTION(S2_pstorerbnewt_zomap)
{
    snprintf(i, n,"if (P%d) memb(R%d+#0)=R%d.new",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerbnewt_zomap_alt
 * Source Syntax: if Pv4 memb(Rs32)=Nt8.new
 * Dest Syntax: if (Pv4) memb(Rs32+#0)=Nt8.new
 *
 */
MAP_FUNCTION(S2_pstorerbnewt_zomap_alt)
{
    snprintf(i, n,"if (P%d) memb(R%d+#0)=R%d.new",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerbt_zomap
 * Source Syntax: if (Pv4) memb(Rs32)=Rt32
 * Dest Syntax: if (Pv4) memb(Rs32+#0)=Rt32
 *
 */
MAP_FUNCTION(S2_pstorerbt_zomap)
{
    snprintf(i, n,"if (P%d) memb(R%d+#0)=R%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerbt_zomap_alt
 * Source Syntax: if Pv4 memb(Rs32)=Rt32
 * Dest Syntax: if (Pv4) memb(Rs32+#0)=Rt32
 *
 */
MAP_FUNCTION(S2_pstorerbt_zomap_alt)
{
    snprintf(i, n,"if (P%d) memb(R%d+#0)=R%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerdf_zomap
 * Source Syntax: if (!Pv4) memd(Rs32)=Rtt32
 * Dest Syntax: if (!Pv4) memd(Rs32+#0)=Rtt32
 *
 */
MAP_FUNCTION(S2_pstorerdf_zomap)
{
    snprintf(i, n,"if (!P%d) memd(R%d+#0)=R%d:%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2)+1,GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerdf_zomap_alt
 * Source Syntax: if !Pv4 memd(Rs32)=Rtt32
 * Dest Syntax: if (!Pv4) memd(Rs32+#0)=Rtt32
 *
 */
MAP_FUNCTION(S2_pstorerdf_zomap_alt)
{
    snprintf(i, n,"if (!P%d) memd(R%d+#0)=R%d:%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2)+1,GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerdt_zomap
 * Source Syntax: if (Pv4) memd(Rs32)=Rtt32
 * Dest Syntax: if (Pv4) memd(Rs32+#0)=Rtt32
 *
 */
MAP_FUNCTION(S2_pstorerdt_zomap)
{
    snprintf(i, n,"if (P%d) memd(R%d+#0)=R%d:%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2)+1,GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerdt_zomap_alt
 * Source Syntax: if Pv4 memd(Rs32)=Rtt32
 * Dest Syntax: if (Pv4) memd(Rs32+#0)=Rtt32
 *
 */
MAP_FUNCTION(S2_pstorerdt_zomap_alt)
{
    snprintf(i, n,"if (P%d) memd(R%d+#0)=R%d:%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2)+1,GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerff_zomap
 * Source Syntax: if (!Pv4) memh(Rs32)=Rt.H32
 * Dest Syntax: if (!Pv4) memh(Rs32+#0)=Rt.H32
 *
 */
MAP_FUNCTION(S2_pstorerff_zomap)
{
    snprintf(i, n,"if (!P%d) memh(R%d+#0)=R%d.h",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerff_zomap_alt
 * Source Syntax: if !Pv4 memh(Rs32)=Rt.H32
 * Dest Syntax: if (!Pv4) memh(Rs32+#0)=Rt.H32
 *
 */
MAP_FUNCTION(S2_pstorerff_zomap_alt)
{
    snprintf(i, n,"if (!P%d) memh(R%d+#0)=R%d.h",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerft_zomap
 * Source Syntax: if (Pv4) memh(Rs32)=Rt.H32
 * Dest Syntax: if (Pv4) memh(Rs32+#0)=Rt.H32
 *
 */
MAP_FUNCTION(S2_pstorerft_zomap)
{
    snprintf(i, n,"if (P%d) memh(R%d+#0)=R%d.h",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerft_zomap_alt
 * Source Syntax: if Pv4 memh(Rs32)=Rt.H32
 * Dest Syntax: if (Pv4) memh(Rs32+#0)=Rt.H32
 *
 */
MAP_FUNCTION(S2_pstorerft_zomap_alt)
{
    snprintf(i, n,"if (P%d) memh(R%d+#0)=R%d.h",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerhf_zomap
 * Source Syntax: if (!Pv4) memh(Rs32)=Rt32
 * Dest Syntax: if (!Pv4) memh(Rs32+#0)=Rt32
 *
 */
MAP_FUNCTION(S2_pstorerhf_zomap)
{
    snprintf(i, n,"if (!P%d) memh(R%d+#0)=R%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerhf_zomap_alt
 * Source Syntax: if !Pv4 memh(Rs32)=Rt32
 * Dest Syntax: if (!Pv4) memh(Rs32+#0)=Rt32
 *
 */
MAP_FUNCTION(S2_pstorerhf_zomap_alt)
{
    snprintf(i, n,"if (!P%d) memh(R%d+#0)=R%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerhnewf_zomap
 * Source Syntax: if (!Pv4) memh(Rs32)=Nt8.new
 * Dest Syntax: if (!Pv4) memh(Rs32+#0)=Nt8.new
 *
 */
MAP_FUNCTION(S2_pstorerhnewf_zomap)
{
    snprintf(i, n,"if (!P%d) memh(R%d+#0)=R%d.new",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerhnewf_zomap_alt
 * Source Syntax: if !Pv4 memh(Rs32)=Nt8.new
 * Dest Syntax: if (!Pv4) memh(Rs32+#0)=Nt8.new
 *
 */
MAP_FUNCTION(S2_pstorerhnewf_zomap_alt)
{
    snprintf(i, n,"if (!P%d) memh(R%d+#0)=R%d.new",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerhnewt_zomap
 * Source Syntax: if (Pv4) memh(Rs32)=Nt8.new
 * Dest Syntax: if (Pv4) memh(Rs32+#0)=Nt8.new
 *
 */
MAP_FUNCTION(S2_pstorerhnewt_zomap)
{
    snprintf(i, n,"if (P%d) memh(R%d+#0)=R%d.new",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerhnewt_zomap_alt
 * Source Syntax: if Pv4 memh(Rs32)=Nt8.new
 * Dest Syntax: if (Pv4) memh(Rs32+#0)=Nt8.new
 *
 */
MAP_FUNCTION(S2_pstorerhnewt_zomap_alt)
{
    snprintf(i, n,"if (P%d) memh(R%d+#0)=R%d.new",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerht_zomap
 * Source Syntax: if (Pv4) memh(Rs32)=Rt32
 * Dest Syntax: if (Pv4) memh(Rs32+#0)=Rt32
 *
 */
MAP_FUNCTION(S2_pstorerht_zomap)
{
    snprintf(i, n,"if (P%d) memh(R%d+#0)=R%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerht_zomap_alt
 * Source Syntax: if Pv4 memh(Rs32)=Rt32
 * Dest Syntax: if (Pv4) memh(Rs32+#0)=Rt32
 *
 */
MAP_FUNCTION(S2_pstorerht_zomap_alt)
{
    snprintf(i, n,"if (P%d) memh(R%d+#0)=R%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerif_zomap
 * Source Syntax: if (!Pv4) memw(Rs32)=Rt32
 * Dest Syntax: if (!Pv4) memw(Rs32+#0)=Rt32
 *
 */
MAP_FUNCTION(S2_pstorerif_zomap)
{
    snprintf(i, n,"if (!P%d) memw(R%d+#0)=R%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerif_zomap_alt
 * Source Syntax: if !Pv4 memw(Rs32)=Rt32
 * Dest Syntax: if (!Pv4) memw(Rs32+#0)=Rt32
 *
 */
MAP_FUNCTION(S2_pstorerif_zomap_alt)
{
    snprintf(i, n,"if (!P%d) memw(R%d+#0)=R%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerinewf_zomap
 * Source Syntax: if (!Pv4) memw(Rs32)=Nt8.new
 * Dest Syntax: if (!Pv4) memw(Rs32+#0)=Nt8.new
 *
 */
MAP_FUNCTION(S2_pstorerinewf_zomap)
{
    snprintf(i, n,"if (!P%d) memw(R%d+#0)=R%d.new",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerinewf_zomap_alt
 * Source Syntax: if !Pv4 memw(Rs32)=Nt8.new
 * Dest Syntax: if (!Pv4) memw(Rs32+#0)=Nt8.new
 *
 */
MAP_FUNCTION(S2_pstorerinewf_zomap_alt)
{
    snprintf(i, n,"if (!P%d) memw(R%d+#0)=R%d.new",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerinewt_zomap
 * Source Syntax: if (Pv4) memw(Rs32)=Nt8.new
 * Dest Syntax: if (Pv4) memw(Rs32+#0)=Nt8.new
 *
 */
MAP_FUNCTION(S2_pstorerinewt_zomap)
{
    snprintf(i, n,"if (P%d) memw(R%d+#0)=R%d.new",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerinewt_zomap_alt
 * Source Syntax: if Pv4 memw(Rs32)=Nt8.new
 * Dest Syntax: if (Pv4) memw(Rs32+#0)=Nt8.new
 *
 */
MAP_FUNCTION(S2_pstorerinewt_zomap_alt)
{
    snprintf(i, n,"if (P%d) memw(R%d+#0)=R%d.new",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerit_zomap
 * Source Syntax: if (Pv4) memw(Rs32)=Rt32
 * Dest Syntax: if (Pv4) memw(Rs32+#0)=Rt32
 *
 */
MAP_FUNCTION(S2_pstorerit_zomap)
{
    snprintf(i, n,"if (P%d) memw(R%d+#0)=R%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S2_pstorerit_zomap_alt
 * Source Syntax: if Pv4 memw(Rs32)=Rt32
 * Dest Syntax: if (Pv4) memw(Rs32+#0)=Rt32
 *
 */
MAP_FUNCTION(S2_pstorerit_zomap_alt)
{
    snprintf(i, n,"if (P%d) memw(R%d+#0)=R%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S2_storerb_zomap
 * Source Syntax: memb(Rs32)=Rt32
 * Dest Syntax: memb(Rs32+#0)=Rt32
 *
 */
MAP_FUNCTION(S2_storerb_zomap)
{
    snprintf(i, n,"memb(R%d+#0)=R%d",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: S2_storerbnew_zomap
 * Source Syntax: memb(Rs32)=Nt8.new
 * Dest Syntax: memb(Rs32+#0)=Nt8.new
 *
 */
MAP_FUNCTION(S2_storerbnew_zomap)
{
    snprintf(i, n,"memb(R%d+#0)=R%d.new",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: S2_storerd_zomap
 * Source Syntax: memd(Rs32)=Rtt32
 * Dest Syntax: memd(Rs32+#0)=Rtt32
 *
 */
MAP_FUNCTION(S2_storerd_zomap)
{
    snprintf(i, n,"memd(R%d+#0)=R%d:%d",GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1));
}

/*
 * Source Tag: S2_storerf_zomap
 * Source Syntax: memh(Rs32)=Rt.H32
 * Dest Syntax: memh(Rs32+#0)=Rt.H32
 *
 */
MAP_FUNCTION(S2_storerf_zomap)
{
    snprintf(i, n,"memh(R%d+#0)=R%d.h",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: S2_storerh_zomap
 * Source Syntax: memh(Rs32)=Rt32
 * Dest Syntax: memh(Rs32+#0)=Rt32
 *
 */
MAP_FUNCTION(S2_storerh_zomap)
{
    snprintf(i, n,"memh(R%d+#0)=R%d",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: S2_storerhnew_zomap
 * Source Syntax: memh(Rs32)=Nt8.new
 * Dest Syntax: memh(Rs32+#0)=Nt8.new
 *
 */
MAP_FUNCTION(S2_storerhnew_zomap)
{
    snprintf(i, n,"memh(R%d+#0)=R%d.new",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: S2_storeri_zomap
 * Source Syntax: memw(Rs32)=Rt32
 * Dest Syntax: memw(Rs32+#0)=Rt32
 *
 */
MAP_FUNCTION(S2_storeri_zomap)
{
    snprintf(i, n,"memw(R%d+#0)=R%d",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: S2_storerinew_zomap
 * Source Syntax: memw(Rs32)=Nt8.new
 * Dest Syntax: memw(Rs32+#0)=Nt8.new
 *
 */
MAP_FUNCTION(S2_storerinew_zomap)
{
    snprintf(i, n,"memw(R%d+#0)=R%d.new",GET_OP_VAL(0),GET_OP_VAL(1));
}

/*
 * Source Tag: S2_tableidxb_goodsyntax
 * Source Syntax: Rx32=tableidxb(Rs32,#u4,#U5)
 * Dest Syntax: Rx32=tableidxb(Rs32,#u4,#U5):raw
 *
 */
MAP_FUNCTION(S2_tableidxb_goodsyntax)
{
    snprintf(i, n,"R%d=tableidxb(R%d,#%s,#%s):raw",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2),GET_OP_STR(3));
}

/*
 * Source Tag: S2_tableidxd_goodsyntax
 * Source Syntax: Rx32=tableidxd(Rs32,#u4,#U5)
 * Dest Syntax: Rx32=tableidxd(Rs32,#u4,#U5-3):raw
 *
 */
MAP_FUNCTION(S2_tableidxd_goodsyntax)
{
    snprintf(i, n,"R%d=tableidxd(R%d,#%s,#%s-3):raw",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2),GET_OP_STR(3));
}

/*
 * Source Tag: S2_tableidxh_goodsyntax
 * Source Syntax: Rx32=tableidxh(Rs32,#u4,#U5)
 * Dest Syntax: Rx32=tableidxh(Rs32,#u4,#U5-1):raw
 *
 */
MAP_FUNCTION(S2_tableidxh_goodsyntax)
{
    snprintf(i, n,"R%d=tableidxh(R%d,#%s,#%s-1):raw",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2),GET_OP_STR(3));
}

/*
 * Source Tag: S2_tableidxw_goodsyntax
 * Source Syntax: Rx32=tableidxw(Rs32,#u4,#U5)
 * Dest Syntax: Rx32=tableidxw(Rs32,#u4,#U5-2):raw
 *
 */
MAP_FUNCTION(S2_tableidxw_goodsyntax)
{
    snprintf(i, n,"R%d=tableidxw(R%d,#%s,#%s-2):raw",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2),GET_OP_STR(3));
}

/*
 * Source Tag: S4_pstorerbfnew_zomap
 * Source Syntax: if (!Pv4.new) memb(Rs32)=Rt32
 * Dest Syntax: if (!Pv4.new) memb(Rs32+#0)=Rt32
 *
 */
MAP_FUNCTION(S4_pstorerbfnew_zomap)
{
    snprintf(i, n,"if (!P%d.new) memb(R%d+#0)=R%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerbfnew_zomap_alt
 * Source Syntax: if !Pv4.new memb(Rs32)=Rt32
 * Dest Syntax: if (!Pv4.new) memb(Rs32+#0)=Rt32
 *
 */
MAP_FUNCTION(S4_pstorerbfnew_zomap_alt)
{
    snprintf(i, n,"if (!P%d.new) memb(R%d+#0)=R%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerbnewfnew_zomap
 * Source Syntax: if (!Pv4.new) memb(Rs32)=Nt8.new
 * Dest Syntax: if (!Pv4.new) memb(Rs32+#0)=Nt8.new
 *
 */
MAP_FUNCTION(S4_pstorerbnewfnew_zomap)
{
    snprintf(i, n,"if (!P%d.new) memb(R%d+#0)=R%d.new",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerbnewfnew_zomap_alt
 * Source Syntax: if !Pv4.new memb(Rs32)=Nt8.new
 * Dest Syntax: if (!Pv4.new) memb(Rs32+#0)=Nt8.new
 *
 */
MAP_FUNCTION(S4_pstorerbnewfnew_zomap_alt)
{
    snprintf(i, n,"if (!P%d.new) memb(R%d+#0)=R%d.new",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerbnewtnew_zomap
 * Source Syntax: if (Pv4.new) memb(Rs32)=Nt8.new
 * Dest Syntax: if (Pv4.new) memb(Rs32+#0)=Nt8.new
 *
 */
MAP_FUNCTION(S4_pstorerbnewtnew_zomap)
{
    snprintf(i, n,"if (P%d.new) memb(R%d+#0)=R%d.new",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerbnewtnew_zomap_alt
 * Source Syntax: if Pv4.new memb(Rs32)=Nt8.new
 * Dest Syntax: if (Pv4.new) memb(Rs32+#0)=Nt8.new
 *
 */
MAP_FUNCTION(S4_pstorerbnewtnew_zomap_alt)
{
    snprintf(i, n,"if (P%d.new) memb(R%d+#0)=R%d.new",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerbtnew_zomap
 * Source Syntax: if (Pv4.new) memb(Rs32)=Rt32
 * Dest Syntax: if (Pv4.new) memb(Rs32+#0)=Rt32
 *
 */
MAP_FUNCTION(S4_pstorerbtnew_zomap)
{
    snprintf(i, n,"if (P%d.new) memb(R%d+#0)=R%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerbtnew_zomap_alt
 * Source Syntax: if Pv4.new memb(Rs32)=Rt32
 * Dest Syntax: if (Pv4.new) memb(Rs32+#0)=Rt32
 *
 */
MAP_FUNCTION(S4_pstorerbtnew_zomap_alt)
{
    snprintf(i, n,"if (P%d.new) memb(R%d+#0)=R%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerdfnew_zomap
 * Source Syntax: if (!Pv4.new) memd(Rs32)=Rtt32
 * Dest Syntax: if (!Pv4.new) memd(Rs32+#0)=Rtt32
 *
 */
MAP_FUNCTION(S4_pstorerdfnew_zomap)
{
    snprintf(i, n,"if (!P%d.new) memd(R%d+#0)=R%d:%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2)+1,GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerdfnew_zomap_alt
 * Source Syntax: if !Pv4.new memd(Rs32)=Rtt32
 * Dest Syntax: if (!Pv4.new) memd(Rs32+#0)=Rtt32
 *
 */
MAP_FUNCTION(S4_pstorerdfnew_zomap_alt)
{
    snprintf(i, n,"if (!P%d.new) memd(R%d+#0)=R%d:%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2)+1,GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerdtnew_zomap
 * Source Syntax: if (Pv4.new) memd(Rs32)=Rtt32
 * Dest Syntax: if (Pv4.new) memd(Rs32+#0)=Rtt32
 *
 */
MAP_FUNCTION(S4_pstorerdtnew_zomap)
{
    snprintf(i, n,"if (P%d.new) memd(R%d+#0)=R%d:%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2)+1,GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerdtnew_zomap_alt
 * Source Syntax: if Pv4.new memd(Rs32)=Rtt32
 * Dest Syntax: if (Pv4.new) memd(Rs32+#0)=Rtt32
 *
 */
MAP_FUNCTION(S4_pstorerdtnew_zomap_alt)
{
    snprintf(i, n,"if (P%d.new) memd(R%d+#0)=R%d:%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2)+1,GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerffnew_zomap
 * Source Syntax: if (!Pv4.new) memh(Rs32)=Rt.H32
 * Dest Syntax: if (!Pv4.new) memh(Rs32+#0)=Rt.H32
 *
 */
MAP_FUNCTION(S4_pstorerffnew_zomap)
{
    snprintf(i, n,"if (!P%d.new) memh(R%d+#0)=R%d.h",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerffnew_zomap_alt
 * Source Syntax: if !Pv4.new memh(Rs32)=Rt.H32
 * Dest Syntax: if (!Pv4.new) memh(Rs32+#0)=Rt.H32
 *
 */
MAP_FUNCTION(S4_pstorerffnew_zomap_alt)
{
    snprintf(i, n,"if (!P%d.new) memh(R%d+#0)=R%d.h",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerftnew_zomap
 * Source Syntax: if (Pv4.new) memh(Rs32)=Rt.H32
 * Dest Syntax: if (Pv4.new) memh(Rs32+#0)=Rt.H32
 *
 */
MAP_FUNCTION(S4_pstorerftnew_zomap)
{
    snprintf(i, n,"if (P%d.new) memh(R%d+#0)=R%d.h",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerftnew_zomap_alt
 * Source Syntax: if Pv4.new memh(Rs32)=Rt.H32
 * Dest Syntax: if (Pv4.new) memh(Rs32+#0)=Rt.H32
 *
 */
MAP_FUNCTION(S4_pstorerftnew_zomap_alt)
{
    snprintf(i, n,"if (P%d.new) memh(R%d+#0)=R%d.h",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerhfnew_zomap
 * Source Syntax: if (!Pv4.new) memh(Rs32)=Rt32
 * Dest Syntax: if (!Pv4.new) memh(Rs32+#0)=Rt32
 *
 */
MAP_FUNCTION(S4_pstorerhfnew_zomap)
{
    snprintf(i, n,"if (!P%d.new) memh(R%d+#0)=R%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerhfnew_zomap_alt
 * Source Syntax: if !Pv4.new memh(Rs32)=Rt32
 * Dest Syntax: if (!Pv4.new) memh(Rs32+#0)=Rt32
 *
 */
MAP_FUNCTION(S4_pstorerhfnew_zomap_alt)
{
    snprintf(i, n,"if (!P%d.new) memh(R%d+#0)=R%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerhnewfnew_zomap
 * Source Syntax: if (!Pv4.new) memh(Rs32)=Nt8.new
 * Dest Syntax: if (!Pv4.new) memh(Rs32+#0)=Nt8.new
 *
 */
MAP_FUNCTION(S4_pstorerhnewfnew_zomap)
{
    snprintf(i, n,"if (!P%d.new) memh(R%d+#0)=R%d.new",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerhnewfnew_zomap_alt
 * Source Syntax: if !Pv4.new memh(Rs32)=Nt8.new
 * Dest Syntax: if (!Pv4.new) memh(Rs32+#0)=Nt8.new
 *
 */
MAP_FUNCTION(S4_pstorerhnewfnew_zomap_alt)
{
    snprintf(i, n,"if (!P%d.new) memh(R%d+#0)=R%d.new",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerhnewtnew_zomap
 * Source Syntax: if (Pv4.new) memh(Rs32)=Nt8.new
 * Dest Syntax: if (Pv4.new) memh(Rs32+#0)=Nt8.new
 *
 */
MAP_FUNCTION(S4_pstorerhnewtnew_zomap)
{
    snprintf(i, n,"if (P%d.new) memh(R%d+#0)=R%d.new",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerhnewtnew_zomap_alt
 * Source Syntax: if Pv4.new memh(Rs32)=Nt8.new
 * Dest Syntax: if (Pv4.new) memh(Rs32+#0)=Nt8.new
 *
 */
MAP_FUNCTION(S4_pstorerhnewtnew_zomap_alt)
{
    snprintf(i, n,"if (P%d.new) memh(R%d+#0)=R%d.new",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerhtnew_zomap
 * Source Syntax: if (Pv4.new) memh(Rs32)=Rt32
 * Dest Syntax: if (Pv4.new) memh(Rs32+#0)=Rt32
 *
 */
MAP_FUNCTION(S4_pstorerhtnew_zomap)
{
    snprintf(i, n,"if (P%d.new) memh(R%d+#0)=R%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerhtnew_zomap_alt
 * Source Syntax: if Pv4.new memh(Rs32)=Rt32
 * Dest Syntax: if (Pv4.new) memh(Rs32+#0)=Rt32
 *
 */
MAP_FUNCTION(S4_pstorerhtnew_zomap_alt)
{
    snprintf(i, n,"if (P%d.new) memh(R%d+#0)=R%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerifnew_zomap
 * Source Syntax: if (!Pv4.new) memw(Rs32)=Rt32
 * Dest Syntax: if (!Pv4.new) memw(Rs32+#0)=Rt32
 *
 */
MAP_FUNCTION(S4_pstorerifnew_zomap)
{
    snprintf(i, n,"if (!P%d.new) memw(R%d+#0)=R%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerifnew_zomap_alt
 * Source Syntax: if !Pv4.new memw(Rs32)=Rt32
 * Dest Syntax: if (!Pv4.new) memw(Rs32+#0)=Rt32
 *
 */
MAP_FUNCTION(S4_pstorerifnew_zomap_alt)
{
    snprintf(i, n,"if (!P%d.new) memw(R%d+#0)=R%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerinewfnew_zomap
 * Source Syntax: if (!Pv4.new) memw(Rs32)=Nt8.new
 * Dest Syntax: if (!Pv4.new) memw(Rs32+#0)=Nt8.new
 *
 */
MAP_FUNCTION(S4_pstorerinewfnew_zomap)
{
    snprintf(i, n,"if (!P%d.new) memw(R%d+#0)=R%d.new",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerinewfnew_zomap_alt
 * Source Syntax: if !Pv4.new memw(Rs32)=Nt8.new
 * Dest Syntax: if (!Pv4.new) memw(Rs32+#0)=Nt8.new
 *
 */
MAP_FUNCTION(S4_pstorerinewfnew_zomap_alt)
{
    snprintf(i, n,"if (!P%d.new) memw(R%d+#0)=R%d.new",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerinewtnew_zomap
 * Source Syntax: if (Pv4.new) memw(Rs32)=Nt8.new
 * Dest Syntax: if (Pv4.new) memw(Rs32+#0)=Nt8.new
 *
 */
MAP_FUNCTION(S4_pstorerinewtnew_zomap)
{
    snprintf(i, n,"if (P%d.new) memw(R%d+#0)=R%d.new",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstorerinewtnew_zomap_alt
 * Source Syntax: if Pv4.new memw(Rs32)=Nt8.new
 * Dest Syntax: if (Pv4.new) memw(Rs32+#0)=Nt8.new
 *
 */
MAP_FUNCTION(S4_pstorerinewtnew_zomap_alt)
{
    snprintf(i, n,"if (P%d.new) memw(R%d+#0)=R%d.new",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstoreritnew_zomap
 * Source Syntax: if (Pv4.new) memw(Rs32)=Rt32
 * Dest Syntax: if (Pv4.new) memw(Rs32+#0)=Rt32
 *
 */
MAP_FUNCTION(S4_pstoreritnew_zomap)
{
    snprintf(i, n,"if (P%d.new) memw(R%d+#0)=R%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S4_pstoreritnew_zomap_alt
 * Source Syntax: if Pv4.new memw(Rs32)=Rt32
 * Dest Syntax: if (Pv4.new) memw(Rs32+#0)=Rt32
 *
 */
MAP_FUNCTION(S4_pstoreritnew_zomap_alt)
{
    snprintf(i, n,"if (P%d.new) memw(R%d+#0)=R%d",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_VAL(2));
}

/*
 * Source Tag: S4_storeirb_zomap
 * Source Syntax: memb(Rs32)=#S8
 * Dest Syntax: memb(Rs32+#0)=#S8
 *
 */
MAP_FUNCTION(S4_storeirb_zomap)
{
    snprintf(i, n,"memb(R%d+#0)=#%s",GET_OP_VAL(0),GET_OP_STR(1));
}

/*
 * Source Tag: S4_storeirbf_zomap
 * Source Syntax: if (!Pv4) memb(Rs32)=#S6
 * Dest Syntax: if (!Pv4) memb(Rs32+#0)=#S6
 *
 */
MAP_FUNCTION(S4_storeirbf_zomap)
{
    snprintf(i, n,"if (!P%d) memb(R%d+#0)=#%s",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
}

/*
 * Source Tag: S4_storeirbf_zomap_alt
 * Source Syntax: if !Pv4 memb(Rs32)=#S6
 * Dest Syntax: if (!Pv4) memb(Rs32+#0)=#S6
 *
 */
MAP_FUNCTION(S4_storeirbf_zomap_alt)
{
    snprintf(i, n,"if (!P%d) memb(R%d+#0)=#%s",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
}

/*
 * Source Tag: S4_storeirbfnew_zomap
 * Source Syntax: if (!Pv4.new) memb(Rs32)=#S6
 * Dest Syntax: if (!Pv4.new) memb(Rs32+#0)=#S6
 *
 */
MAP_FUNCTION(S4_storeirbfnew_zomap)
{
    snprintf(i, n,"if (!P%d.new) memb(R%d+#0)=#%s",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
}

/*
 * Source Tag: S4_storeirbfnew_zomap_alt
 * Source Syntax: if !Pv4.new memb(Rs32)=#S6
 * Dest Syntax: if (!Pv4.new) memb(Rs32+#0)=#S6
 *
 */
MAP_FUNCTION(S4_storeirbfnew_zomap_alt)
{
    snprintf(i, n,"if (!P%d.new) memb(R%d+#0)=#%s",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
}

/*
 * Source Tag: S4_storeirbt_zomap
 * Source Syntax: if (Pv4) memb(Rs32)=#S6
 * Dest Syntax: if (Pv4) memb(Rs32+#0)=#S6
 *
 */
MAP_FUNCTION(S4_storeirbt_zomap)
{
    snprintf(i, n,"if (P%d) memb(R%d+#0)=#%s",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
}

/*
 * Source Tag: S4_storeirbt_zomap_alt
 * Source Syntax: if Pv4 memb(Rs32)=#S6
 * Dest Syntax: if (Pv4) memb(Rs32+#0)=#S6
 *
 */
MAP_FUNCTION(S4_storeirbt_zomap_alt)
{
    snprintf(i, n,"if (P%d) memb(R%d+#0)=#%s",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
}

/*
 * Source Tag: S4_storeirbtnew_zomap
 * Source Syntax: if (Pv4.new) memb(Rs32)=#S6
 * Dest Syntax: if (Pv4.new) memb(Rs32+#0)=#S6
 *
 */
MAP_FUNCTION(S4_storeirbtnew_zomap)
{
    snprintf(i, n,"if (P%d.new) memb(R%d+#0)=#%s",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
}

/*
 * Source Tag: S4_storeirbtnew_zomap_alt
 * Source Syntax: if Pv4.new memb(Rs32)=#S6
 * Dest Syntax: if (Pv4.new) memb(Rs32+#0)=#S6
 *
 */
MAP_FUNCTION(S4_storeirbtnew_zomap_alt)
{
    snprintf(i, n,"if (P%d.new) memb(R%d+#0)=#%s",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
}

/*
 * Source Tag: S4_storeirh_zomap
 * Source Syntax: memh(Rs32)=#S8
 * Dest Syntax: memh(Rs32+#0)=#S8
 *
 */
MAP_FUNCTION(S4_storeirh_zomap)
{
    snprintf(i, n,"memh(R%d+#0)=#%s",GET_OP_VAL(0),GET_OP_STR(1));
}

/*
 * Source Tag: S4_storeirhf_zomap
 * Source Syntax: if (!Pv4) memh(Rs32)=#S6
 * Dest Syntax: if (!Pv4) memh(Rs32+#0)=#S6
 *
 */
MAP_FUNCTION(S4_storeirhf_zomap)
{
    snprintf(i, n,"if (!P%d) memh(R%d+#0)=#%s",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
}

/*
 * Source Tag: S4_storeirhf_zomap_alt
 * Source Syntax: if !Pv4 memh(Rs32)=#S6
 * Dest Syntax: if (!Pv4) memh(Rs32+#0)=#S6
 *
 */
MAP_FUNCTION(S4_storeirhf_zomap_alt)
{
    snprintf(i, n,"if (!P%d) memh(R%d+#0)=#%s",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
}

/*
 * Source Tag: S4_storeirhfnew_zomap
 * Source Syntax: if (!Pv4.new) memh(Rs32)=#S6
 * Dest Syntax: if (!Pv4.new) memh(Rs32+#0)=#S6
 *
 */
MAP_FUNCTION(S4_storeirhfnew_zomap)
{
    snprintf(i, n,"if (!P%d.new) memh(R%d+#0)=#%s",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
}

/*
 * Source Tag: S4_storeirhfnew_zomap_alt
 * Source Syntax: if !Pv4.new memh(Rs32)=#S6
 * Dest Syntax: if (!Pv4.new) memh(Rs32+#0)=#S6
 *
 */
MAP_FUNCTION(S4_storeirhfnew_zomap_alt)
{
    snprintf(i, n,"if (!P%d.new) memh(R%d+#0)=#%s",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
}

/*
 * Source Tag: S4_storeirht_zomap
 * Source Syntax: if (Pv4) memh(Rs32)=#S6
 * Dest Syntax: if (Pv4) memh(Rs32+#0)=#S6
 *
 */
MAP_FUNCTION(S4_storeirht_zomap)
{
    snprintf(i, n,"if (P%d) memh(R%d+#0)=#%s",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
}

/*
 * Source Tag: S4_storeirht_zomap_alt
 * Source Syntax: if Pv4 memh(Rs32)=#S6
 * Dest Syntax: if (Pv4) memh(Rs32+#0)=#S6
 *
 */
MAP_FUNCTION(S4_storeirht_zomap_alt)
{
    snprintf(i, n,"if (P%d) memh(R%d+#0)=#%s",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
}

/*
 * Source Tag: S4_storeirhtnew_zomap
 * Source Syntax: if (Pv4.new) memh(Rs32)=#S6
 * Dest Syntax: if (Pv4.new) memh(Rs32+#0)=#S6
 *
 */
MAP_FUNCTION(S4_storeirhtnew_zomap)
{
    snprintf(i, n,"if (P%d.new) memh(R%d+#0)=#%s",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
}

/*
 * Source Tag: S4_storeirhtnew_zomap_alt
 * Source Syntax: if Pv4.new memh(Rs32)=#S6
 * Dest Syntax: if (Pv4.new) memh(Rs32+#0)=#S6
 *
 */
MAP_FUNCTION(S4_storeirhtnew_zomap_alt)
{
    snprintf(i, n,"if (P%d.new) memh(R%d+#0)=#%s",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
}

/*
 * Source Tag: S4_storeiri_zomap
 * Source Syntax: memw(Rs32)=#S8
 * Dest Syntax: memw(Rs32+#0)=#S8
 *
 */
MAP_FUNCTION(S4_storeiri_zomap)
{
    snprintf(i, n,"memw(R%d+#0)=#%s",GET_OP_VAL(0),GET_OP_STR(1));
}

/*
 * Source Tag: S4_storeirif_zomap
 * Source Syntax: if (!Pv4) memw(Rs32)=#S6
 * Dest Syntax: if (!Pv4) memw(Rs32+#0)=#S6
 *
 */
MAP_FUNCTION(S4_storeirif_zomap)
{
    snprintf(i, n,"if (!P%d) memw(R%d+#0)=#%s",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
}

/*
 * Source Tag: S4_storeirif_zomap_alt
 * Source Syntax: if !Pv4 memw(Rs32)=#S6
 * Dest Syntax: if (!Pv4) memw(Rs32+#0)=#S6
 *
 */
MAP_FUNCTION(S4_storeirif_zomap_alt)
{
    snprintf(i, n,"if (!P%d) memw(R%d+#0)=#%s",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
}

/*
 * Source Tag: S4_storeirifnew_zomap
 * Source Syntax: if (!Pv4.new) memw(Rs32)=#S6
 * Dest Syntax: if (!Pv4.new) memw(Rs32+#0)=#S6
 *
 */
MAP_FUNCTION(S4_storeirifnew_zomap)
{
    snprintf(i, n,"if (!P%d.new) memw(R%d+#0)=#%s",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
}

/*
 * Source Tag: S4_storeirifnew_zomap_alt
 * Source Syntax: if !Pv4.new memw(Rs32)=#S6
 * Dest Syntax: if (!Pv4.new) memw(Rs32+#0)=#S6
 *
 */
MAP_FUNCTION(S4_storeirifnew_zomap_alt)
{
    snprintf(i, n,"if (!P%d.new) memw(R%d+#0)=#%s",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
}

/*
 * Source Tag: S4_storeirit_zomap
 * Source Syntax: if (Pv4) memw(Rs32)=#S6
 * Dest Syntax: if (Pv4) memw(Rs32+#0)=#S6
 *
 */
MAP_FUNCTION(S4_storeirit_zomap)
{
    snprintf(i, n,"if (P%d) memw(R%d+#0)=#%s",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
}

/*
 * Source Tag: S4_storeirit_zomap_alt
 * Source Syntax: if Pv4 memw(Rs32)=#S6
 * Dest Syntax: if (Pv4) memw(Rs32+#0)=#S6
 *
 */
MAP_FUNCTION(S4_storeirit_zomap_alt)
{
    snprintf(i, n,"if (P%d) memw(R%d+#0)=#%s",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
}

/*
 * Source Tag: S4_storeiritnew_zomap
 * Source Syntax: if (Pv4.new) memw(Rs32)=#S6
 * Dest Syntax: if (Pv4.new) memw(Rs32+#0)=#S6
 *
 */
MAP_FUNCTION(S4_storeiritnew_zomap)
{
    snprintf(i, n,"if (P%d.new) memw(R%d+#0)=#%s",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
}

/*
 * Source Tag: S4_storeiritnew_zomap_alt
 * Source Syntax: if Pv4.new memw(Rs32)=#S6
 * Dest Syntax: if (Pv4.new) memw(Rs32+#0)=#S6
 *
 */
MAP_FUNCTION(S4_storeiritnew_zomap_alt)
{
    snprintf(i, n,"if (P%d.new) memw(R%d+#0)=#%s",GET_OP_VAL(0),GET_OP_VAL(1),GET_OP_STR(2));
}

/*
 * Source Tag: S5_asrhub_rnd_sat_goodsyntax
 * Source Syntax: Rd32=vasrhub(Rss32,#u4):rnd:sat
 * Dest Syntax: Rd32=vsathub(Rss32)
 * Dest Syntax2: Rd32=vasrhub(Rss32,#u4-1):raw
 * Condition: #u4==0
 *
 */
MAP_FUNCTION(S5_asrhub_rnd_sat_goodsyntax)
{
	if (GET_OP_VAL(2)==0) {
		snprintf(i, n,"R%d=vsathub(R%d:%d)",GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1));
	} else {
		snprintf(i, n,"R%d=vasrhub(R%d:%d,#%s-1):raw",GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1),GET_OP_STR(2));
	}
}

/*
 * Source Tag: S5_vasrhrnd_goodsyntax
 * Source Syntax: Rdd32=vasrh(Rss32,#u4):rnd
 * Dest Syntax: Rdd32=Rss32
 * Dest Syntax2: Rdd32=vasrh(Rss32,#u4-1):raw
 * Condition: #u4==0
 *
 */
MAP_FUNCTION(S5_vasrhrnd_goodsyntax)
{
	if (GET_OP_VAL(2)==0) {
		snprintf(i, n,"R%d:%d=R%d:%d",GET_OP_VAL(0)+1,GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1));
	} else {
		snprintf(i, n,"R%d:%d=vasrh(R%d:%d,#%s-1):raw",GET_OP_VAL(0)+1,GET_OP_VAL(0),GET_OP_VAL(1)+1,GET_OP_VAL(1),GET_OP_STR(2));
	}
}

/*
 * Source Tag: Y2_crswap_old
 * Source Syntax: crswap(Rx32,sgp)
 * Dest Syntax: crswap(Rx32,sgp0)
 *
 */
MAP_FUNCTION(Y2_crswap_old)
{
    snprintf(i, n,"crswap(R%d,sgp0)",GET_OP_VAL(0));
}

/*
 * Source Tag: Y2_dcfetch
 * Source Syntax: dcfetch(Rs32)
 * Dest Syntax: dcfetch(Rs32+#0)
 *
 */
MAP_FUNCTION(Y2_dcfetch)
{
    snprintf(i, n,"dcfetch(R%d+#0)",GET_OP_VAL(0));
}

