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
import com.rashed.pharmacy.util.*;

public class GenericController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String INSERT_OR_EDIT = "/jsp/product/genericAdd.jsp";
	private static String LIST_GENERIC = "/jsp/product/genericList.jsp";
	private static String ENQUIRY = "/jsp/product/genericEnquiry.jsp";
	private ProductCategoryDAO pcdao;
	private GenericDAO gdao;
	
	String action = "";
	String message = "";
	
       
    public GenericController() {
        super();
        pcdao = new ProductCategoryDAO();
        gdao = new GenericDAO();
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
			String generic_id = request.getParameter("generic_id");
			gdao.delete(generic_id);
			forward=LIST_GENERIC;
			request.setAttribute("generics", gdao.getAllGeneric());
			message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			forward = INSERT_OR_EDIT;
			String generic_id = request.getParameter("generic_id");
			Generic g = gdao.getGenericById(generic_id);
			request.setAttribute("generic", g);
			// for get all the ProductCategory_id when update generic [S]
			request.setAttribute("allProductCategory", pcdao.getAllProductCategory());
			// for get all the ProductCategory_id when update generic [E]
			// selected other respective id during update [S]
			request.setAttribute("selectedGenericId", gdao.getSelectedOtherID(generic_id).getGeneric_id());
			request.setAttribute("selectedProductCategoryId", gdao.getSelectedOtherID(generic_id).getProduct_category_id());
			// selected other respective id during update [E]
		} else if(action.equalsIgnoreCase("genericList")){
			forward = LIST_GENERIC;
			request.setAttribute("generics", gdao.getAllGeneric());
		}  else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String generic_id = request.getParameter("generic_id");
			Generic g = gdao.getGenericById(generic_id);
			request.setAttribute("generic", g);
		} else {
			forward = INSERT_OR_EDIT;
			// for get all the ProductCategory_id when add generic [S]
			request.setAttribute("allProductCategory", pcdao.getAllProductCategory());
			// for get all the ProductCategory_id when add generic [E]
			// generated auto increment id during add [S]
			request.setAttribute("genericId", gdao.getGenericID().getGeneric_id());
			// generated auto increment id during add [E]
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("======action======="+ action);
		
		Generic g = new Generic();
		
		g.setGeneric_id(request.getParameter("generic_id"));
		g.setGeneric_name(request.getParameter("generic_name"));
		g.setProduct_category_id(request.getParameter("product_category_id"));
		g.setIndications(request.getParameter("indications"));
		g.setAdult_dose(request.getParameter("adult_dose"));
		g.setChild_dose(request.getParameter("child_dose"));
		g.setRenal_dose(request.getParameter("renal_dose"));
		g.setAdministrations(request.getParameter("administrations"));
		g.setContraindications(request.getParameter("contraindications"));
		g.setSide_effects(request.getParameter("side_effects"));
		g.setPrecautions_warnings(request.getParameter("precautions_warnings"));
		g.setPregnancy_category(request.getParameter("pregnancy_category"));
		g.setTherapeutic_class(request.getParameter("therapeutic_class"));
		g.setMode_of_action(request.getParameter("mode_of_action"));
		g.setInteraction(request.getParameter("interaction"));
		g.setCreated(request.getParameter("created"));
		g.setUpdated(request.getParameter("updated"));
		
		String generic_id = request.getParameter("generic_id");
		String generic_name = request.getParameter("generic_name");
		//String message = "Success!";
		if(action.equalsIgnoreCase("save")){
			gdao.save(g);
		} else if(action.equalsIgnoreCase("edit")){
			g.setGeneric_id(generic_id);
			gdao.update(g);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(LIST_GENERIC);
		if(action.equalsIgnoreCase("save")){
			message = "Data Inserted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			message = "Successfully Data Updated!!!";
			request.setAttribute("success", message);
		}
		request.setAttribute("generics", gdao.getAllGeneric());
		
		rd.forward(request, response);
	}

}
