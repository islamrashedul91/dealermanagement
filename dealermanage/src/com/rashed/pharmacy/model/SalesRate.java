package com.rashed.pharmacy.model;

public class SalesRate {
	
	private String sales_rate_id;	
	private double rate_percent;	
	private String description;		
	private String created;			
	private String updated;			
	private String created_by;		
	private String updated_by;
	
	public String getSales_rate_id() {
		return sales_rate_id;
	}
	public void setSales_rate_id(String sales_rate_id) {
		this.sales_rate_id = sales_rate_id;
	}
	public double getRate_percent() {
		return rate_percent;
	}
	public void setRate_percent(double rate_percent) {
		this.rate_percent = rate_percent;
	}
	public String getDescription() {
		return description;
	}
	public void setDescription(String description) {
		this.description = description;
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
	public String getCreated_by() {
		return created_by;
	}
	public void setCreated_by(String created_by) {
		this.created_by = created_by;
	}
	public String getUpdated_by() {
		return updated_by;
	}
	public void setUpdated_by(String updated_by) {
		this.updated_by = updated_by;
	}

}
