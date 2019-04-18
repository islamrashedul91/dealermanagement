package com.rashed.pharmacy.controller;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.google.zxing.WriterException;
import com.rashed.pharmacy.model.ProductCategory;
import com.rashed.pharmacy.dao.CompanyDAO;
import com.rashed.pharmacy.dao.ProductCategoryDAO;
import com.rashed.pharmacy.model.Generic;
import com.rashed.pharmacy.dao.GenericDAO;
import com.rashed.pharmacy.model.Brand;
import com.rashed.pharmacy.dao.BrandDAO;
import com.rashed.pharmacy.model.PackPiceces;
import com.rashed.pharmacy.dao.PackPicecesDAO;
import com.rashed.pharmacy.model.ProductType;
import com.rashed.pharmacy.dao.ProductTypeDAO;
import com.rashed.pharmacy.model.Product;
import com.rashed.pharmacy.dao.ProductDAO;
import com.rashed.pharmacy.util.*;

public class ProductController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String INSERT_OR_EDIT = "/jsp/product/productAdd.jsp";
	private static String LIST_PRODUCT = "/jsp/product/productList.jsp";
	private static String ENQUIRY = "/jsp/product/productEnquiry.jsp";
	private static String LIST_GUESTPRODUCT = "guestProductList.jsp";
	private static String USAGES = "/jsp/product/productUsages.jsp";
	private ProductCategoryDAO pcdao;
	private GenericDAO gdao;
	private BrandDAO bdao;
	private PackPicecesDAO ppdao;
	private ProductTypeDAO ptdao;
	private CompanyDAO cdao;
	private ProductDAO pdao;
	
	String action = "";
	String message = "";
	
       
    public ProductController() {
        super();
        pcdao = new ProductCategoryDAO();
        gdao = new GenericDAO();
        bdao = new BrandDAO();
        ppdao = new PackPicecesDAO();
        ptdao = new ProductTypeDAO();
        cdao = new CompanyDAO();
        pdao = new ProductDAO();
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String forward="";
		action = request.getParameter("action");
		// for set the action in session [S]
		HttpSession session = request.getSession();
		session.setAttribute("action", action);
		// for set the action in session [E]
		
		if(action.equalsIgnoreCase("delete")){
			//int id=Integer.parseInt(request.getParameter("id"));
			String product_id = request.getParameter("product_id");
			pdao.delete(product_id);
			forward=LIST_PRODUCT;
			request.setAttribute("products", pdao.getAllProduct());
			message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			forward = INSERT_OR_EDIT;
			String product_id = request.getParameter("product_id");
			Product p = pdao.getProductById(product_id);
			request.setAttribute("product", p);
			// for get all the ProductCategory_id when update Product [S]
			request.setAttribute("allProductCategory", pcdao.getAllProductCategory());
			// for get all the ProductCategory_id when update Product [E]
			// for get all the Generic when update Product [S]
			request.setAttribute("allGeneric", gdao.getAllGeneric());
			// for get all the Generic when update Product [E]
			// for get all the Brand when update Product [S]
			request.setAttribute("allBrand", bdao.getAllBrand());
			// for get all the Brand when update Product [E]
			// for get all the Pack Pieces when update Product [S]
			request.setAttribute("allPackPieces", ppdao.getAllPackPiceces());
			// for get all the Pack Pieces when update Product [E]
			// for get all the Product Type when update Product [S]
			request.setAttribute("allProductType", ptdao.getAllProductType());
			// for get all the Product Type when update Product [E]
			// for get all the Company Id when update Product [S]
			request.setAttribute("allCompany", cdao.getAllCompany());
			// for get all the Company Id when update Product [E]
			// selected other respective id during update [S]
			request.setAttribute("selectedProductTypeId", pdao.getSelectedOtherID(product_id).getProduct_type_id());
			request.setAttribute("selectedBrandId", pdao.getSelectedOtherID(product_id).getBrand_id());
			request.setAttribute("selectedProductCategoryId", pdao.getSelectedOtherID(product_id).getProduct_category_id());
			request.setAttribute("selectedGenericId", pdao.getSelectedOtherID(product_id).getGeneric_id());
			request.setAttribute("selectedPackPicecesId", pdao.getSelectedOtherID(product_id).getPack_piceces_id());
			request.setAttribute("selectedCompanyId", pdao.getSelectedOtherID(product_id).getCompany_id());
			// selected other respective id during update [E]
		} else if(action.equalsIgnoreCase("productList")){
			forward = LIST_PRODUCT;
			request.setAttribute("products", pdao.getAllProduct());
		} else if(action.equalsIgnoreCase("guestProductList")){
			forward = LIST_GUESTPRODUCT;
			request.setAttribute("products", pdao.getAllProduct());
		} else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String product_id = request.getParameter("product_id");
			Product p = pdao.getProductById(product_id);
			request.setAttribute("product", p);
		} else if(action.equalsIgnoreCase("usages")){
			forward = USAGES;
			String product_id = request.getParameter("product_id");
			Product p = pdao.getProductById(product_id);
			request.setAttribute("product", p);
			// get value from more than one table [S]
			request.setAttribute("indications", pdao.getValueFromDifferentTable(product_id).getIndications());
			request.setAttribute("usagesProduct", pdao.getValueFromDifferentTable(product_id));
			// get value from more than one table [E]
		} else {
			forward = INSERT_OR_EDIT;
			// for get all the ProductCategory_id when add Product [S]
			request.setAttribute("allProductCategory", pcdao.getAllProductCategory());
			// for get all the ProductCategory_id when add Product [E]
			// for get all the Generic when add Product [S]
			request.setAttribute("allGeneric", gdao.getAllGeneric());
			// for get all the Generic when add Product [E]
			// for get all the Brand when add Product [S]
			request.setAttribute("allBrand", bdao.getAllBrand());
			// for get all the Brand when add Product [E]
			// for get all the Pack Pieces when add Product [S]
			request.setAttribute("allPackPieces", ppdao.getAllPackPiceces());
			// for get all the Pack Pieces when add Product [E]
			// for get all the Product Type when add Product [S]
			request.setAttribute("allProductType", ptdao.getAllProductType());
			// for get all the Product Type when add Product [E]
			// for get all the Company Id when add Product [S]
			request.setAttribute("allCompany", cdao.getAllCompany());
			// for get all the Company Id when add Product [E]
			// generated auto increment id during add [S]
			request.setAttribute("productId", pdao.getProductID().getProduct_id());
			// generated auto increment id during add [E]
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("======action======="+ action);
		
		Product p = new Product();
		
		p.setProduct_id(request.getParameter("product_id"));
		p.setProduct_name(request.getParameter("product_name"));
		p.setProduct_type_id(request.getParameter("product_type_id"));
		p.setProduct_type(request.getParameter("product_type"));
		p.setStength(request.getParameter("stength"));
		p.setBrand_id(request.getParameter("brand_id"));
		p.setBrand_name(request.getParameter("brand_name"));
		p.setProduct_category_id(request.getParameter("product_category_id"));
		p.setProduct_category_name(request.getParameter("product_category_name"));
		p.setGeneric_id(request.getParameter("generic_id"));
		p.setGeneric_name(request.getParameter("generic_name"));
		p.setPack_piceces_id(request.getParameter("pack_piceces_id"));
		p.setPack_type(request.getParameter("pack_type"));
		p.setPack_size(request.getParameter("pack_size"));
		p.setPiceces(Integer.parseInt(request.getParameter("piceces")));
		p.setRate_per_piceces(Double.parseDouble(request.getParameter("rate_per_piceces")));
		p.setRate_per_box(Double.parseDouble(request.getParameter("rate_per_box")));
		p.setTp_price(Double.parseDouble(request.getParameter("tp_price")));
		p.setMrp_price(Double.parseDouble(request.getParameter("mrp_price")));
		p.setTotal_tp_price(Double.parseDouble(request.getParameter("total_tp_price")));
		p.setTotal_mrp_price(Double.parseDouble(request.getParameter("total_mrp_price")));
		p.setStock(request.getParameter("stock"));
		p.setBonus_id(request.getParameter("bonus_id"));
		p.setCreated(request.getParameter("created"));
		p.setUpdated(request.getParameter("updated"));
		p.setCompany_id(request.getParameter("company_id"));
		p.setCompany_name(request.getParameter("company_name"));
		
		String product_id = request.getParameter("product_id");

		if(action.equalsIgnoreCase("save")){
			pdao.save(p);
		} else if(action.equalsIgnoreCase("edit")){
			p.setProduct_id(product_id);
			pdao.update(p);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(LIST_PRODUCT);
		if(action.equalsIgnoreCase("save")){
			message = "Data Inserted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			message = "Successfully Data Updated!!!";
			request.setAttribute("success", message);
		}
		request.setAttribute("products", pdao.getAllProduct());
		
		rd.forward(request, response);
	}

}