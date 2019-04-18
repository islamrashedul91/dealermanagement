package com.rashed.pharmacy.model;

public class Purchase {
	
	private String purchase_id;						
	private String purchase_type;  	
	private String requisition_id;	
	private String product_id;		
	private String product_name;
	private String pack_type;		
	private String pack_size;		
	private int piceces;			
	private String bonus_id;		
	private String bonus_name;		
	private String order_pack;		
	private int order_quantity;	
	private double rate_per_piceces;
	private double rate_per_box;	
	private double tp_price;		
	private double total_tp_price;	
	private double discount_amt;	
	private double total_amount;	
	private String needed_date_time;
	private String from_account_id;	
	private String to_account_id;	
	private String order_status;	
	private String delivery_status;	
	private String created;			
	private String updated;			
	private String created_by;		
	private String updated_by;
	
	public String getPurchase_id() {
		return purchase_id;
	}
	public String getPurchase_type() {
		return purchase_type;
	}
	public String getRequisition_id() {
		return requisition_id;
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
	public double getRate_per_piceces() {
		return rate_per_piceces;
	}
	public double getRate_per_box() {
		return rate_per_box;
	}
	public double getTp_price() {
		return tp_price;
	}
	public double getTotal_tp_price() {
		return total_tp_price;
	}
	public double getDiscount_amt() {
		return discount_amt;
	}
	public double getTotal_amount() {
		return total_amount;
	}
	public String getNeeded_date_time() {
		return needed_date_time;
	}
	public String getFrom_account_id() {
		return from_account_id;
	}
	public String getTo_account_id() {
		return to_account_id;
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
	public String getCreated_by() {
		return created_by;
	}
	public String getUpdated_by() {
		return updated_by;
	}
	public void setPurchase_id(String purchase_id) {
		this.purchase_id = purchase_id;
	}
	public void setPurchase_type(String purchase_type) {
		this.purchase_type = purchase_type;
	}
	public void setRequisition_id(String requisition_id) {
		this.requisition_id = requisition_id;
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
	public void setRate_per_piceces(double rate_per_piceces) {
		this.rate_per_piceces = rate_per_piceces;
	}
	public void setRate_per_box(double rate_per_box) {
		this.rate_per_box = rate_per_box;
	}
	public void setTp_price(double tp_price) {
		this.tp_price = tp_price;
	}
	public void setTotal_tp_price(double total_tp_price) {
		this.total_tp_price = total_tp_price;
	}
	public void setDiscount_amt(double discount_amt) {
		this.discount_amt = discount_amt;
	}
	public void setTotal_amount(double total_amount) {
		this.total_amount = total_amount;
	}
	public void setNeeded_date_time(String needed_date_time) {
		this.needed_date_time = needed_date_time;
	}
	public void setFrom_account_id(String from_account_id) {
		this.from_account_id = from_account_id;
	}
	public void setTo_account_id(String to_account_id) {
		this.to_account_id = to_account_id;
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
	public void setCreated_by(String created_by) {
		this.created_by = created_by;
	}
	public void setUpdated_by(String updated_by) {
		this.updated_by = updated_by;
	}

}
