package com.rashed.pharmacy.controller;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import com.google.zxing.WriterException;

import com.rashed.pharmacy.model.ProductType;
import com.rashed.pharmacy.dao.ProductTypeDAO;
import com.rashed.pharmacy.util.*;

public class ProductTypeController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String INSERT_OR_EDIT = "/jsp/product/productTypeAdd.jsp";
	private static String LIST_PRODUCTTYPE = "/jsp/product/productTypeList.jsp";
	private static String ENQUIRY = "/jsp/product/productTypeEnquiry.jsp";
	private ProductTypeDAO dao;
	
	String action = "";
	String message = "";
	
       
    public ProductTypeController() {
        super();
        dao = new ProductTypeDAO();
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
			String product_type_id = request.getParameter("product_type_id");
			dao.delete(product_type_id);
			forward=LIST_PRODUCTTYPE;
			request.setAttribute("productTypes", dao.getAllProductType());
			message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			forward = INSERT_OR_EDIT;
			String product_type_id = request.getParameter("product_type_id");
			ProductType pt = dao.getProductTypeById(product_type_id);
			request.setAttribute("productType", pt);
		} else if(action.equalsIgnoreCase("productTypeList")){
			forward = LIST_PRODUCTTYPE;
			request.setAttribute("productTypes", dao.getAllProductType());
		}  else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String product_type_id = request.getParameter("product_type_id");
			ProductType pt = dao.getProductTypeById(product_type_id);
			request.setAttribute("productType", pt);
		} else {
			forward = INSERT_OR_EDIT;
			// generated auto increment id during add [S]
			request.setAttribute("productTypeId", dao.getProductTypeID().getProduct_type_id());
			// generated auto increment id during add [E]
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("======action======="+ action);
		
		ProductType pt = new ProductType();
		
		pt.setProduct_type_id(request.getParameter("product_type_id"));
		pt.setProduct_type(request.getParameter("product_type"));
		pt.setStength(request.getParameter("stength"));
		pt.setCreated(request.getParameter("created"));
		pt.setUpdated(request.getParameter("updated"));
		
		String product_type_id = request.getParameter("product_type_id");
		
		if(action.equalsIgnoreCase("save")){
			dao.save(pt);
		} else if(action.equalsIgnoreCase("edit")){
			pt.setProduct_type_id(product_type_id);
			dao.update(pt);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(LIST_PRODUCTTYPE);
		if(action.equalsIgnoreCase("save")){
			message = "Data Inserted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			message = "Successfully Data Updated!!!";
			request.setAttribute("success", message);
		}
		request.setAttribute("productTypes", dao.getAllProductType());
		
		rd.forward(request, response);
	}

}
