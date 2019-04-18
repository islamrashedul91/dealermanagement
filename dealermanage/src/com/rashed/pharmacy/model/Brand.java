package com.rashed.pharmacy.model;

public class Brand {
	
	private String brand_id;							
	private String brand_name;			
	private String product_category_id;	
	private String generic_id;			
	private String generic_name;		
	private String created;				
	private String updated;
	private String company_id;
	private String company_name;
	
	public String getBrand_id() {
		return brand_id;
	}
	public void setBrand_id(String brand_id) {
		this.brand_id = brand_id;
	}
	public String getBrand_name() {
		return brand_name;
	}
	public void setBrand_name(String brand_name) {
		this.brand_name = brand_name;
	}
	public String getProduct_category_id() {
		return product_category_id;
	}
	public void setProduct_category_id(String product_category_id) {
		this.product_category_id = product_category_id;
	}
	public String getGeneric_id() {
		return generic_id;
	}
	public void setGeneric_id(String generic_id) {
		this.generic_id = generic_id;
	}
	public String getGeneric_name() {
		return generic_name;
	}
	public void setGeneric_name(String generic_name) {
		this.generic_name = generic_name;
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
	public String getCompany_id() {
		return company_id;
	}
	public void setCompany_id(String company_id) {
		this.company_id = company_id;
	}
	public String getCompany_name() {
		return company_name;
	}
	public void setCompany_name(String company_name) {
		this.company_name = company_name;
	}

}
