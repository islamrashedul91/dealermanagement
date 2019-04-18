package com.rashed.pharmacy.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import com.rashed.pharmacy.model.Product;
import com.rashed.pharmacy.model.Generic;
import com.rashed.pharmacy.util.*;

public class ProductDAO {
	
	private Connection con;
	private static Connection conn;
	GetHeader getHeader = new GetHeader();
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
	SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
	Date date = new Date();  
	String strDate = formatter.format(date);
	
	public ProductDAO(){
		//con  = DbUtil.getConnection();
	}
	
	
	public void save(Product p){
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO product(product_id, product_name, product_type_id, product_type, stength, brand_id, brand_name, product_category_id, product_category_name, generic_id, generic_name, pack_piceces_id, pack_type, pack_size, piceces, rate_per_piceces, rate_per_box, tp_price, mrp_price, total_tp_price, total_mrp_price, stock, bonus_id, created, updated, company_id, company_name) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO product(product_id, product_name, product_type_id, product_type, stength, brand_id, brand_name, product_category_id, product_category_name, generic_id, generic_name, pack_piceces_id, pack_type, pack_size, piceces, rate_per_piceces, rate_per_box, tp_price, mrp_price, total_tp_price, total_mrp_price, stock, bonus_id, created, updated, company_id, company_name) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			ps.setString(1, p.getProduct_id());
			ps.setString(2, p.getProduct_name());
			ps.setString(3, p.getProduct_type_id());
			ps.setString(4, p.getProduct_type());
			ps.setString(5, p.getStength());
			ps.setString(6, p.getBrand_id());
			ps.setString(7, p.getBrand_name());
			ps.setString(8, p.getProduct_category_id());
			ps.setString(9, p.getProduct_category_name());
			ps.setString(10, p.getGeneric_id());
			ps.setString(11, p.getGeneric_name());
			ps.setString(12, p.getPack_piceces_id());
			ps.setString(13, p.getPack_type());
			ps.setString(14, p.getPack_size());
			ps.setInt(15, p.getPiceces());
			ps.setDouble(16, p.getRate_per_piceces());
			ps.setDouble(17, p.getRate_per_box());
			ps.setDouble(18, p.getTp_price());
			ps.setDouble(19, p.getMrp_price());
			ps.setDouble(20, p.getTotal_tp_price());
			ps.setDouble(21, p.getTotal_mrp_price());
			ps.setString(22, p.getStock());
			ps.setString(23, p.getBonus_id());
			ps.setString(24, p.getCreated());
			ps.setString(25, p.getUpdated());
			ps.setString(26, p.getCompany_id());
			ps.setString(27, p.getCompany_name());
			
			ps.executeUpdate();
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	public void delete(String product_id){
		try{
			//PreparedStatement ps = con.prepareStatement("DELETE FROM product WHERE product_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM product WHERE product_id=?");
			
			ps.setString(1, product_id);
			
			ps.executeUpdate();
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	public void stockUpdate(String product_id, int intOrderQuantity){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE product set stock=?, updated=? where product_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE product set stock=?, updated=? where product_id=?");
			
			ProductDAO pd = new ProductDAO();
			String strStock = pd.getProductById(product_id).getStock();
			int intStock = Integer.parseInt(strStock);
			
			int stockHas = intStock - intOrderQuantity;
			
			ps.setString(1, String.valueOf(stockHas));
			ps.setString(2, strDate);
			ps.setString(3, product_id);
			
			ps.executeUpdate();		
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	public void purchaseStockUpdate(String product_id, int intOrderQuantity){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE product set stock=?, updated=? where product_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE product set stock=?, updated=? where product_id=?");
			
			ProductDAO pd = new ProductDAO();
			String strStock = pd.getProductById(product_id).getStock();
			int intStock = Integer.parseInt(strStock);
			
			int stockHas = intStock + intOrderQuantity;
			
			ps.setString(1, String.valueOf(stockHas));
			ps.setString(2, strDate);
			ps.setString(3, product_id);
			
			ps.executeUpdate();		
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	public void returnStockUpdate(String product_id, int intOrderQuantity){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE product set stock=?, updated=? where product_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE product set stock=?, updated=? where product_id=?");
			
			ProductDAO pd = new ProductDAO();
			String strStock = pd.getProductById(product_id).getStock();
			int intStock = Integer.parseInt(strStock);
			
			int stockHas = intStock + intOrderQuantity;
			
			ps.setString(1, String.valueOf(stockHas));
			ps.setString(2, strDate);
			ps.setString(3, product_id);
			
			ps.executeUpdate();		
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	public void update(Product p){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE product set product_name=?, product_type_id=?, product_type=?, stength=?, brand_id=?, brand_name=?, product_category_id=?, product_category_name=?, generic_id=?, generic_name=?, pack_piceces_id=?, pack_type=?, pack_size=?, piceces=?, rate_per_piceces=?, rate_per_box=?, tp_price=?, mrp_price=?, total_tp_price=?, total_mrp_price=?, stock=?, bonus_id=?, created=?, updated=?, company_id=?, company_name=? where product_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE product set product_name=?, product_type_id=?, product_type=?, stength=?, brand_id=?, brand_name=?, product_category_id=?, product_category_name=?, generic_id=?, generic_name=?, pack_piceces_id=?, pack_type=?, pack_size=?, piceces=?, rate_per_piceces=?, rate_per_box=?, tp_price=?, mrp_price=?, total_tp_price=?, total_mrp_price=?, stock=?, bonus_id=?, created=?, updated=?, company_id=?, company_name=? where product_id=?");
			
			ps.setString(1, p.getProduct_name());
			ps.setString(2, p.getProduct_type_id());
			ps.setString(3, p.getProduct_type());
			ps.setString(4, p.getStength());
			ps.setString(5, p.getBrand_id());
			ps.setString(6, p.getBrand_name());
			ps.setString(7, p.getProduct_category_id());
			ps.setString(8, p.getProduct_category_name());
			ps.setString(9, p.getGeneric_id());
			ps.setString(10, p.getGeneric_name());
			ps.setString(11, p.getPack_piceces_id());
			ps.setString(12, p.getPack_type());
			ps.setString(13, p.getPack_size());
			ps.setInt(14, p.getPiceces());
			ps.setDouble(15, p.getRate_per_piceces());
			ps.setDouble(16, p.getRate_per_box());
			ps.setDouble(17, p.getTp_price());
			ps.setDouble(18, p.getMrp_price());
			ps.setDouble(19, p.getTotal_tp_price());
			ps.setDouble(20, p.getTotal_mrp_price());
			ps.setString(21, p.getStock());
			ps.setString(22, p.getBonus_id());
			ps.setString(23, p.getCreated());
			ps.setString(24, p.getUpdated());
			ps.setString(25, p.getCompany_id());
			ps.setString(26, p.getCompany_name());
			ps.setString(27, p.getProduct_id());
			
			ps.executeUpdate();		
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	public List<Product> getAllProduct(){
		List<Product> list = new ArrayList<Product>();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT product_id, product_name, product_type_id, product_type, stength, brand_id, brand_name, product_category_id, product_category_name, generic_id, generic_name, pack_piceces_id, pack_type, pack_size, piceces, rate_per_piceces, rate_per_box, tp_price, mrp_price, total_tp_price, total_mrp_price, stock, bonus_id, created, updated, company_id, company_name FROM product");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT product_id, product_name, product_type_id, product_type, stength, brand_id, brand_name, product_category_id, product_category_name, generic_id, generic_name, pack_piceces_id, pack_type, pack_size, piceces, rate_per_piceces, rate_per_box, tp_price, mrp_price, total_tp_price, total_mrp_price, stock, bonus_id, created, updated, company_id, company_name FROM product");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				Product p = new Product();				
				
				p.setProduct_id(rs.getString(1));
				p.setProduct_name(rs.getString(2));
				p.setProduct_type_id(rs.getString(3));
				p.setProduct_type(rs.getString(4));
				p.setStength(rs.getString(5));
				p.setBrand_id(rs.getString(6));
				p.setBrand_name(rs.getString(7));
				p.setProduct_category_id(rs.getString(8));
				p.setProduct_category_name(rs.getString(9));
				p.setGeneric_id(rs.getString(10));
				p.setGeneric_name(rs.getString(11));
				p.setPack_piceces_id(rs.getString(12));
				p.setPack_type(rs.getString(13));
				p.setPack_size(rs.getString(14));
				p.setPiceces(rs.getInt(15));
				p.setRate_per_piceces(rs.getDouble(16));
				p.setRate_per_box(rs.getDouble(17));
				p.setTp_price(rs.getDouble(18));
				p.setMrp_price(rs.getDouble(19));
				p.setTotal_tp_price(rs.getDouble(20));
				p.setTotal_mrp_price(rs.getDouble(21));
				p.setStock(rs.getString(22));
				p.setBonus_id(rs.getString(23));
				p.setCreated(rs.getString(24));
				p.setUpdated(rs.getString(25));
				p.setCompany_id(rs.getString(26));
				p.setCompany_name(rs.getString(27));
				
				list.add(p);				
			}
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(rs != null){
				try {
					rs.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
		
		return list;
	}
	
	public Product getProductById(String product_id){
		Product p = new Product();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT product_id, product_name, product_type_id, product_type, stength, brand_id, brand_name, product_category_id, product_category_name, generic_id, generic_name, pack_piceces_id, pack_type, pack_size, piceces, rate_per_piceces, rate_per_box, tp_price, mrp_price, total_tp_price, total_mrp_price, stock, bonus_id, created, updated, company_id, company_name FROM product where product_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT product_id, product_name, product_type_id, product_type, stength, brand_id, brand_name, product_category_id, product_category_name, generic_id, generic_name, pack_piceces_id, pack_type, pack_size, piceces, rate_per_piceces, rate_per_box, tp_price, mrp_price, total_tp_price, total_mrp_price, stock, bonus_id, created, updated, company_id, company_name FROM product where product_id=?");
			
			ps.setString(1, product_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				p.setProduct_id(rs.getString(1));
				p.setProduct_name(rs.getString(2));
				p.setProduct_type_id(rs.getString(3));
				p.setProduct_type(rs.getString(4));
				p.setStength(rs.getString(5));
				p.setBrand_id(rs.getString(6));
				p.setBrand_name(rs.getString(7));
				p.setProduct_category_id(rs.getString(8));
				p.setProduct_category_name(rs.getString(9));
				p.setGeneric_id(rs.getString(10));
				p.setGeneric_name(rs.getString(11));
				p.setPack_piceces_id(rs.getString(12));
				p.setPack_type(rs.getString(13));
				p.setPack_size(rs.getString(14));
				p.setPiceces(rs.getInt(15));
				p.setRate_per_piceces(rs.getDouble(16));
				p.setRate_per_box(rs.getDouble(17));
				p.setTp_price(rs.getDouble(18));
				p.setMrp_price(rs.getDouble(19));
				p.setTotal_tp_price(rs.getDouble(20));
				p.setTotal_mrp_price(rs.getDouble(21));
				p.setStock(rs.getString(22));
				p.setBonus_id(rs.getString(23));
				p.setCreated(rs.getString(24));
				p.setUpdated(rs.getString(25));
				p.setCompany_id(rs.getString(26));
				p.setCompany_name(rs.getString(27));
				
			}
		} catch (Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(rs != null){
				try {
					rs.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}

		return p;
	}
	
	// generated auto increment id during add [S]
	public Product getProductID(){
		Product p = new Product();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT product_id FROM product");
			
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT product_id FROM product");
			
			rs = ps.executeQuery();
			
			int product_id = 0;
			
			if(rs.next() == false) {
				product_id = 1000000000;
				product_id = product_id+1;
				p.setProduct_id("PROD" + String.valueOf(product_id));
			} else {
				if(rs.last()) {
					String strProduct = rs.getString("product_id");
					product_id = Integer.parseInt(strProduct.replaceAll("[^0-9]", ""));
					product_id = product_id+1;
					p.setProduct_id("PROD" + String.valueOf(product_id));
				}
			}
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(rs != null){
				try {
					rs.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
		
		return p;
	}
	// generated auto increment id during add [E]
	
	// selected other respective id during update [S]
	public Product getSelectedOtherID(String product_id){
		Product p = new Product();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT product_id, product_type_id, brand_id, product_category_id, generic_id, pack_piceces_id, company_id FROM product WHERE product_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT product_id, product_type_id, brand_id, product_category_id, generic_id, pack_piceces_id, company_id FROM product WHERE product_id=?");
			
			ps.setString(1, product_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				String strProduct = rs.getString("product_id");
				String strProductType = rs.getString("product_type_id");
				String strBrand = rs.getString("brand_id");
				String strProductCategory = rs.getString("product_category_id");
				String strGeneric = rs.getString("generic_id");
				String strPackPieces = rs.getString("pack_piceces_id");
				String strCompany = rs.getString("company_id");
				
				p.setProduct_id(strProduct);
				p.setProduct_type_id(strProductType);
				p.setBrand_id(strBrand);
				p.setProduct_category_id(strProductCategory);
				p.setGeneric_id(strGeneric);
				p.setPack_piceces_id(strPackPieces);
				p.setCompany_id(strCompany);
				
			}
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(rs != null){
				try {
					rs.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
		
		return p;
	}
	// selected other respective id during update [E]
	
	// get value from more than one table [S]
	public Generic getValueFromDifferentTable(String product_id){
		
		Generic g = new Generic();
		
		try{
			
			/*PreparedStatement ps = con.prepareStatement("SELECT g.generic_id, g.generic_name, g.indications, g.adult_dose, g.child_dose, g.renal_dose, "
					+ "g.administrations, g.contraindications, g.side_effects, g.precautions_warnings, g.pregnancy_category, g.therapeutic_class, "
					+ "g.mode_of_action, g.interaction FROM generic g WHERE g.generic_id = (SELECT p.generic_id FROM product p, generic g "
					+ "WHERE p.generic_id=g.generic_id and p.product_id=?)");*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT g.generic_id, g.generic_name, g.indications, g.adult_dose, g.child_dose, g.renal_dose, "
					+ "g.administrations, g.contraindications, g.side_effects, g.precautions_warnings, g.pregnancy_category, g.therapeutic_class, "
					+ "g.mode_of_action, g.interaction FROM generic g WHERE g.generic_id = (SELECT p.generic_id FROM product p, generic g "
					+ "WHERE p.generic_id=g.generic_id and p.product_id=?)");
			
			ps.setString(1, product_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				String strGeneric = rs.getString("generic_id");
				String strGenericName = rs.getString("generic_name");
				String strIndications = rs.getString("indications");
				String strAdultDose = rs.getString("adult_dose");
				String strChildDose = rs.getString("child_dose");
				String strRenalDose = rs.getString("renal_dose");
				String strAdministrations = rs.getString("administrations");
				String strContraindications= rs.getString("contraindications");
				String strSideEffects = rs.getString("side_effects");
				String strPrecautionsWarnings = rs.getString("precautions_warnings");
				String strPregnancyCategory = rs.getString("pregnancy_category");
				String strTherapeuticClass = rs.getString("therapeutic_class");
				String strModeOfAction = rs.getString("mode_of_action");
				String strInteraction = rs.getString("interaction");
				
				g.setGeneric_id(strGeneric);
				g.setGeneric_name(strGenericName);
				g.setIndications(strIndications);
				g.setAdult_dose(strAdultDose);
				g.setChild_dose(strChildDose);
				g.setRenal_dose(strRenalDose);	
				g.setAdministrations(strAdministrations);
				g.setContraindications(strContraindications);
				g.setSide_effects(strSideEffects);
				g.setPrecautions_warnings(strPrecautionsWarnings);
				g.setPregnancy_category(strPregnancyCategory);
				g.setTherapeutic_class(strTherapeuticClass);
				g.setMode_of_action(strModeOfAction);
				g.setInteraction(strInteraction);
			}
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(rs != null){
				try {
					rs.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
		
		return g;
	}
	// get value from more than one table [E]

}
