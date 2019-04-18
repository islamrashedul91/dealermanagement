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
import com.rashed.pharmacy.dao.ProductCategoryDAO;
import com.rashed.pharmacy.model.Generic;
import com.rashed.pharmacy.dao.GenericDAO;
import com.rashed.pharmacy.model.Company;
import com.rashed.pharmacy.dao.CompanyDAO;
import com.rashed.pharmacy.model.Brand;
import com.rashed.pharmacy.dao.BrandDAO;
import com.rashed.pharmacy.util.*;

public class BrandController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String INSERT_OR_EDIT = "/jsp/product/brandAdd.jsp";
	private static String LIST_BRAND = "/jsp/product/brandList.jsp";
	private static String ENQUIRY = "/jsp/product/brandEnquiry.jsp";
	private ProductCategoryDAO pcdao;
	private GenericDAO gdao;
	private CompanyDAO cdao;
	private BrandDAO bdao;
	
	String action = "";
	String message = "";
	
       
    public BrandController() {
        super();
        pcdao = new ProductCategoryDAO();
        gdao = new GenericDAO();
        cdao = new CompanyDAO();
        bdao = new BrandDAO();
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
			String brand_id = request.getParameter("brand_id");
			bdao.delete(brand_id);
			forward=LIST_BRAND;
			request.setAttribute("brands", bdao.getAllBrand());
			message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			forward = INSERT_OR_EDIT;
			String brand_id = request.getParameter("brand_id");
			Brand b = bdao.getBrandById(brand_id);
			request.setAttribute("brand", b);
			// for get all the ProductCategory_id when update generic [S]
			request.setAttribute("allProductCategory", pcdao.getAllProductCategory());
			// for get all the ProductCategory_id when update generic [E]
			// for get all the Generic when update brand [S]
			request.setAttribute("allGeneric", gdao.getAllGeneric());
			// for get all the Generic when update brand [E]
			// for get all the Company Id when update brand [S]
			request.setAttribute("allCompany", cdao.getAllCompany());
			// for get all the Company Id when update brand [E]
			// selected other respective id during update [S]
			request.setAttribute("selectedBrandId", bdao.getSelectedOtherID(brand_id).getBrand_id());
			request.setAttribute("selectedCompanyId", bdao.getSelectedOtherID(brand_id).getCompany_id());
			request.setAttribute("selectedProductCategoryId", bdao.getSelectedOtherID(brand_id).getProduct_category_id());
			request.setAttribute("selectedGenericId", bdao.getSelectedOtherID(brand_id).getGeneric_id());
			// selected other respective id during update [E]
		} else if(action.equalsIgnoreCase("brandList")){
			forward = LIST_BRAND;
			request.setAttribute("brands", bdao.getAllBrand());
		}  else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String brand_id = request.getParameter("brand_id");
			Brand b = bdao.getBrandById(brand_id);
			request.setAttribute("brand", b);
		} else {
			forward = INSERT_OR_EDIT;
			// for get all the ProductCategory_id when add generic [S]
			request.setAttribute("allProductCategory", pcdao.getAllProductCategory());
			// for get all the ProductCategory_id when add generic [E]
			// for get all the Generic when add brand [S]
			request.setAttribute("allGeneric", gdao.getAllGeneric());
			// for get all the Generic when add brand [E]
			// for get all the Company Id when add brand [S]
			request.setAttribute("allCompany", cdao.getAllCompany());
			// for get all the Company Id when add brand [E]
			// generated auto increment id during add [S]
			request.setAttribute("brandId", bdao.getBrandID().getBrand_id());
			// generated auto increment id during add [E]
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("======action======="+ action);
		
		Brand b = new Brand();
		
		b.setBrand_id(request.getParameter("brand_id"));
		b.setBrand_name(request.getParameter("brand_name"));
		b.setProduct_category_id(request.getParameter("product_category_id"));
		b.setGeneric_id(request.getParameter("generic_id"));
		b.setGeneric_name(request.getParameter("generic_name"));
		b.setCreated(request.getParameter("created"));
		b.setUpdated(request.getParameter("updated"));
		b.setCompany_id(request.getParameter("company_id"));
		b.setCompany_name(request.getParameter("company_name"));
		
		String brand_id = request.getParameter("brand_id");
		String brand_name = request.getParameter("brand_name");

		if(action.equalsIgnoreCase("save")){
			bdao.save(b);
		} else if(action.equalsIgnoreCase("edit")){
			b.setBrand_id(brand_id);
			bdao.update(b);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(LIST_BRAND);
		if(action.equalsIgnoreCase("save")){
			message = "Data Inserted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			message = "Successfully Data Updated!!!";
			request.setAttribute("success", message);
		}
		request.setAttribute("brands", bdao.getAllBrand());
		
		rd.forward(request, response);
	}

}
