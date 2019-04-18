package com.rashed.pharmacy.model;

public class RequisitionProduct {
	
	private String requisition_product_id;			
	private String requisition_id;	
	private String date_time;		
	private String product_id;		
	private String product_name;	
	private String pack_type;		
	private String pack_size;		
	private int piceces;			
	private String bonus_id;		
	private String bonus_name;		
	private String order_pack;		
	private int order_quantity;				
	private double mrp_price;		
	private double total_mrp_price;	
	private double discount_amt;	
	private double total_amount;	
	private String order_status;	
	private String delivery_status;	
	private String created;			
	private String updated;
	
	public String getRequisition_product_id() {
		return requisition_product_id;
	}
	public String getRequisition_id() {
		return requisition_id;
	}
	public String getDate_time() {
		return date_time;
	}
	public String getProduct_id() {
		return product_id;
	}
	public String getProduct_name() {
		return product_name;
	}
	public String getPack_type() {
		return pack_type;
	}
	public String getPack_size() {
		return pack_size;
	}
	public int getPiceces() {
		return piceces;
	}
	public String getBonus_id() {
		return bonus_id;
	}
	public String getBonus_name() {
		return bonus_name;
	}
	public String getOrder_pack() {
		return order_pack;
	}
	public int getOrder_quantity() {
		return order_quantity;
	}
	public double getMrp_price() {
		return mrp_price;
	}
	public double getTotal_mrp_price() {
		return total_mrp_price;
	}
	public double getDiscount_amt() {
		return discount_amt;
	}
	public double getTotal_amount() {
		return total_amount;
	}
	public String getOrder_status() {
		return order_status;
	}
	public String getDelivery_status() {
		return delivery_status;
	}
	public String getCreated() {
		return created;
	}
	public String getUpdated() {
		return updated;
	}
	public void setRequisition_product_id(String requisition_product_id) {
		this.requisition_product_id = requisition_product_id;
	}
	public void setRequisition_id(String requisition_id) {
		this.requisition_id = requisition_id;
	}
	public void setDate_time(String date_time) {
		this.date_time = date_time;
	}
	public void setProduct_id(String product_id) {
		this.product_id = product_id;
	}
	public void setProduct_name(String product_name) {
		this.product_name = product_name;
	}
	public void setPack_type(String pack_type) {
		this.pack_type = pack_type;
	}
	public void setPack_size(String pack_size) {
		this.pack_size = pack_size;
	}
	public void setPiceces(int piceces) {
		this.piceces = piceces;
	}
	public void setBonus_id(String bonus_id) {
		this.bonus_id = bonus_id;
	}
	public void setBonus_name(String bonus_name) {
		this.bonus_name = bonus_name;
	}
	public void setOrder_pack(String order_pack) {
		this.order_pack = order_pack;
	}
	public void setOrder_quantity(int order_quantity) {
		this.order_quantity = order_quantity;
	}
	public void setMrp_price(double mrp_price) {
		this.mrp_price = mrp_price;
	}
	public void setTotal_mrp_price(double total_mrp_price) {
		this.total_mrp_price = total_mrp_price;
	}
	public void setDiscount_amt(double discount_amt) {
		this.discount_amt = discount_amt;
	}
	public void setTotal_amount(double total_amount) {
		this.total_amount = total_amount;
	}
	public void setOrder_status(String order_status) {
		this.order_status = order_status;
	}
	public void setDelivery_status(String delivery_status) {
		this.delivery_status = delivery_status;
	}
	public void setCreated(String created) {
		this.created = created;
	}
	public void setUpdated(String updated) {
		this.updated = updated;
	}

}
