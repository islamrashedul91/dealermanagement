package com.rashed.pharmacy.model;

public class ProductType {
	
	private String product_type_id;	
	private String product_type;	
	private String stength;			
	private String created;			
	private String updated;
	
	public String getProduct_type_id() {
		return product_type_id;
	}
	public void setProduct_type_id(String product_type_id) {
		this.product_type_id = product_type_id;
	}
	public String getProduct_type() {
		return product_type;
	}
	public void setProduct_type(String product_type) {
		this.product_type = product_type;
	}
	public String getStength() {
		return stength;
	}
	public void setStength(String stength) {
		this.stength = stength;
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
