package com.rashed.pharmacy.model;

public class RequisitionMulti {
	
	private String requisition_id;	
	private String date_time;		
	private String customer_id;		
	private String customer_name;   
	private String mobile;         	
	private String needed_date_time;
	private String from_account_id;	
	private String to_account_id;	
	private String salesman_id;
	private double total_amount;
	private String order_status;	
	private String delivery_status;	
	private String created;				
	private String updated;
	
	public String getRequisition_id() {
		return requisition_id;
	}
	public String getDate_time() {
		return date_time;
	}
	public String getCustomer_id() {
		return customer_id;
	}
	public String getCustomer_name() {
		return customer_name;
	}
	public String getMobile() {
		return mobile;
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
	public String getSalesman_id() {
		return salesman_id;
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
	public void setRequisition_id(String requisition_id) {
		this.requisition_id = requisition_id;
	}
	public void setDate_time(String date_time) {
		this.date_time = date_time;
	}
	public void setCustomer_id(String customer_id) {
		this.customer_id = customer_id;
	}
	public void setCustomer_name(String customer_name) {
		this.customer_name = customer_name;
	}
	public void setMobile(String mobile) {
		this.mobile = mobile;
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
	public void setSalesman_id(String salesman_id) {
		this.salesman_id = salesman_id;
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
