package com.rashed.pharmacy.model;

public class ExpenseProduct {
	
	private String expense_product_id;	
	private String expense_id;			
	private String expense_type;  		
	private String date_time;			
	private String category_id;		  	
	private String category_name;		
	private int quantity;			
	private double price;				
	private double total_price;			
	private double discount_amt;		
	private double total_amount;		
	private String order_status;		
	private String expense_status;		
	private String created;				
	private String updated;				
	private String created_by;			
	private String updated_by;
	
	public String getExpense_product_id() {
		return expense_product_id;
	}
	public String getExpense_id() {
		return expense_id;
	}
	public String getExpense_type() {
		return expense_type;
	}
	public String getDate_time() {
		return date_time;
	}
	public String getCategory_id() {
		return category_id;
	}
	public String getCategory_name() {
		return category_name;
	}
	public int getQuantity() {
		return quantity;
	}
	public double getPrice() {
		return price;
	}
	public double getTotal_price() {
		return total_price;
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
	public String getExpense_status() {
		return expense_status;
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
	public void setExpense_product_id(String expense_product_id) {
		this.expense_product_id = expense_product_id;
	}
	public void setExpense_id(String expense_id) {
		this.expense_id = expense_id;
	}
	public void setExpense_type(String expense_type) {
		this.expense_type = expense_type;
	}
	public void setDate_time(String date_time) {
		this.date_time = date_time;
	}
	public void setCategory_id(String category_id) {
		this.category_id = category_id;
	}
	public void setCategory_name(String category_name) {
		this.category_name = category_name;
	}
	public void setQuantity(int quantity) {
		this.quantity = quantity;
	}
	public void setPrice(double price) {
		this.price = price;
	}
	public void setTotal_price(double total_price) {
		this.total_price = total_price;
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
	public void setExpense_status(String expense_status) {
		this.expense_status = expense_status;
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
