package com.rashed.pharmacy.model;

public class Account {
	
	private String account_id;		
	private String account_type;	
	private String account_name;
	private String description;		
	private double previous_balance;
	private double current_balance;	
	private String created;			
	private String updated;
	
	public String getAccount_id() {
		return account_id;
	}
	public void setAccount_id(String account_id) {
		this.account_id = account_id;
	}
	public String getAccount_type() {
		return account_type;
	}
	public void setAccount_type(String account_type) {
		this.account_type = account_type;
	}
	public String getAccount_name() {
		return account_name;
	}
	public void setAccount_name(String account_name) {
		this.account_name = account_name;
	}
	public String getDescription() {
		return description;
	}
	public void setDescription(String description) {
		this.description = description;
	}
	public double getPrevious_balance() {
		return previous_balance;
	}
	public void setPrevious_balance(double previous_balance) {
		this.previous_balance = previous_balance;
	}
	public double getCurrent_balance() {
		return current_balance;
	}
	public void setCurrent_balance(double current_balance) {
		this.current_balance = current_balance;
	}
	public String getCreated() {
		return created;
	}
	public void setCreated(String created) {
		this.created = created;
	}
	public String getUpdated() {
		return updated;
	}
	public void setUpdated(String updated) {
		this.updated = updated;
	}

}
