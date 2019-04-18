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
import com.rashed.pharmacy.util.*;

public class ProductCategoryController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String INSERT_OR_EDIT = "/jsp/product/productCategoryAdd.jsp";
	private static String LIST_PRODUCTCATEGORY = "/jsp/product/productCategoryList.jsp";
	private static String ENQUIRY = "/jsp/product/productCategoryEnquiry.jsp";
	private ProductCategoryDAO dao;
	
	String action = "";
	String message = "";
	
       
    public ProductCategoryController() {
        super();
        dao = new ProductCategoryDAO();
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
			String product_category_id = request.getParameter("product_category_id");
			dao.delete(product_category_id);
			forward=LIST_PRODUCTCATEGORY;
			request.setAttribute("productCategorys", dao.getAllProductCategory());
			message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			forward = INSERT_OR_EDIT;
			String product_category_id = request.getParameter("product_category_id");
			ProductCategory pc = dao.getProductCategoryById(product_category_id);
			request.setAttribute("productCategory", pc);
		} else if(action.equalsIgnoreCase("productCategoryList")){
			forward = LIST_PRODUCTCATEGORY;
			request.setAttribute("productCategorys", dao.getAllProductCategory());
		}  else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String product_category_id = request.getParameter("product_category_id");
			ProductCategory pc = dao.getProductCategoryById(product_category_id);
			request.setAttribute("productCategory", pc);
		} else {
			forward = INSERT_OR_EDIT;
			// generated auto increment id during add [S]
			request.setAttribute("productCategoryId", dao.getProductCategoryID().getProduct_category_id());
			// generated auto increment id during add [E]
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("======action======="+ action);
		
		ProductCategory pc = new ProductCategory();
		
		pc.setProduct_category_id(request.getParameter("product_category_id"));
		pc.setProduct_category_name(request.getParameter("product_category_name"));
		pc.setDescription(request.getParameter("description"));
		pc.setCreated(request.getParameter("created"));
		pc.setUpdated(request.getParameter("updated"));
		
		String product_category_id = request.getParameter("product_category_id");
		String product_category_name = request.getParameter("product_category_name");
		//String message = "Success!";
		if(action.equalsIgnoreCase("save")){
			dao.save(pc);
		} else if(action.equalsIgnoreCase("edit")){
			pc.setProduct_category_id(product_category_id);
			dao.update(pc);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(LIST_PRODUCTCATEGORY);
		if(action.equalsIgnoreCase("save")){
			message = "Data Inserted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			message = "Successfully Data Updated!!!";
			request.setAttribute("success", message);
		}
		request.setAttribute("productCategorys", dao.getAllProductCategory());
		
		rd.forward(request, response);
	}

}