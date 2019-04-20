<jsp:include page="../../base.jsp"></jsp:include>
<br>
<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<%@ page import="java.text.SimpleDateFormat" %>
<%@ page import="java.util.Date" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Online Pharmacy</title>
<link rel="stylesheet" 	href="${pageContext.request.contextPath}/css/table.css">

<script language="JavaScript">

function productTypeChng() {
	oSelectOne = frmSave.elements["product_type_id"];
	index = oSelectOne.selectedIndex;
	var selected_option_text = oSelectOne.options[index].text;
	
	var split_selected_option_text = selected_option_text.split(' - ');
	var finalTextType = split_selected_option_text[1];
	var finalTextStength = split_selected_option_text[2];
	
	document.getElementById('product_type').value = finalTextType;
	document.getElementById('stength').value = finalTextStength;

}

function brandChng() {
	oSelectOne = frmSave.elements["brand_id"];
	index = oSelectOne.selectedIndex;
	var selected_option_text = oSelectOne.options[index].text;
	
	var split_selected_option_text = selected_option_text.split(' - ');
	var finalText = split_selected_option_text[1];
	
	document.getElementById('brand_name').value = finalText;

}

function productCategoryChng() {
	oSelectOne = frmSave.elements["product_category_id"];
	index = oSelectOne.selectedIndex;
	var selected_option_text = oSelectOne.options[index].text;
	
	var split_selected_option_text = selected_option_text.split(' - ');
	var finalText = split_selected_option_text[1];
	
	document.getElementById('product_category_name').value = finalText;

}

function genericChng() {
	//document.getElementById('generic_name').value = document.getElementById('generic_id').value;
	oSelectOne = frmSave.elements["generic_id"];
	index = oSelectOne.selectedIndex;
	var selected_option_text = oSelectOne.options[index].text;
	//document.getElementById('generic_name').value = selected_option_text;
	
	var split_selected_option_text = selected_option_text.split(' - ');
	var finalText = split_selected_option_text[1];
	
	document.getElementById('generic_name').value = finalText;

}

function packChng() {
	oSelectOne = frmSave.elements["pack_piceces_id"];
	index = oSelectOne.selectedIndex;
	var selected_option_text = oSelectOne.options[index].text;
	
	var split_selected_option_text = selected_option_text.split(' - ');
	var finalTextType = split_selected_option_text[1];
	var finalTextSize = split_selected_option_text[2];
	var finalTextPieces = split_selected_option_text[3];
	
	document.getElementById('pack_type').value = finalTextType;
	document.getElementById('pack_size').value = finalTextSize;
	document.getElementById('piceces').value = finalTextPieces;

}

function brandToProduct() {
	
	var brandName = document.getElementById('brand_name').value;
	var stength = document.getElementById('stength').value;
	var productType = document.getElementById('product_type').value;
	
	document.getElementById('product_name').value = brandName+" "+stength+" "+productType;

}

function companyChng() {
	oSelectOne = frmSave.elements["company_id"];
	index = oSelectOne.selectedIndex;
	var selected_option_text = oSelectOne.options[index].text;
	
	var split_selected_option_text = selected_option_text.split(' - ');
	var finalText = split_selected_option_text[1];
	
	document.getElementById('company_name').value = finalText;

}

function perPiecesToPerBox() {
	
	var piceces = document.getElementById('piceces').value;
	var ratePerPiceces = document.getElementById('rate_per_piceces').value;
	var ratePerPicecesToRatePerBox = piceces * ratePerPiceces;
	
	document.getElementById('rate_per_box').value = ratePerPicecesToRatePerBox.toFixed(2);

}

function perBoxToPerPieces() {
	
	var piceces = document.getElementById('piceces').value;
	var ratePerBox = document.getElementById('rate_per_box').value;
	var ratePerBoxToRatePerPiceces = ratePerBox / piceces;
	
	document.getElementById('rate_per_piceces').value = ratePerBoxToRatePerPiceces.toFixed(2);

}

function tpPriceToTotalTpPrice() {
	
	var piceces = document.getElementById('piceces').value;
	var tpPrice = document.getElementById('tp_price').value;
	var totalTpPrice = piceces * tpPrice;
	
	document.getElementById('total_tp_price').value = totalTpPrice.toFixed(2);

}

function totalTpPriceToTpPrice() {
	
	var piceces = document.getElementById('piceces').value;
	var totalTpPrice = document.getElementById('total_tp_price').value;
	var tpPrice = totalTpPrice / piceces;
	
	document.getElementById('tp_price').value = tpPrice.toFixed(2);

}

function mrpPriceToTotalMrpPrice() {
	
	var piceces = document.getElementById('piceces').value;
	var mrpPrice = document.getElementById('mrp_price').value;
	var totalMrpPrice = piceces * mrpPrice;
	
	document.getElementById('total_mrp_price').value = totalMrpPrice.toFixed(2);

}

function totalMrpPriceToMrpPrice() {
	
	var piceces = document.getElementById('piceces').value;
	var totalMrpPrice = document.getElementById('total_mrp_price').value;
	var mrpPrice = totalMrpPrice / piceces;
	
	document.getElementById('mrp_price').value = mrpPrice.toFixed(2);

}

function mrpPriceToTpPrice() {
	
	var mrpPrice = document.getElementById('mrp_price').value;
	var price6 = (mrpPrice * 6) / 100;
	var tpPrice = mrpPrice - price6;
	
	document.getElementById('tp_price').value = tpPrice.toFixed(2);

}

function tpPriceToMrpPrice() {
	
	var tpPrice = document.getElementById('tp_price').value;
	var price6 = (tpPrice * 6) / 100;
	//var mrpPrice = tpPrice + price6; // not working that's why write below code
	var mrpPrice = (tpPrice*1) + (price6*1);
	
	document.getElementById('mrp_price').value = mrpPrice.toFixed(2);

}

function totalMrpPriceToTotalTpPrice() {
	
	var totalMrpPrice = document.getElementById('total_mrp_price').value;
	var price6 = (totalMrpPrice * 6) / 100;
	var totalTpPrice = totalMrpPrice - price6;
	
	document.getElementById('total_tp_price').value = totalTpPrice.toFixed(2);

}

function totalTpPriceToTotalMrpPrice() {
	
	var totalTpPrice = document.getElementById('total_tp_price').value;
	var price6 = (totalTpPrice * 6) / 100;
	//var totalMrpPrice = totalTpPrice + price6; // not working that's why write below code
	var totalMrpPrice = (totalTpPrice*1) + (price6*1);
	
	document.getElementById('total_mrp_price').value = totalMrpPrice.toFixed(2);

}

</script>

</head>
<body>
<%
String action = (String) session.getAttribute("action");
System.out.println("++++++"+action);
%>
<div class="mcontent">
			<div class="titlenav">
				<ul>					
					<li class="title"><a href="">
					<%
					if (action.equalsIgnoreCase("save")) {
					%>
						<td class="PageHeader">Product Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Product Update</td>
					<%
					}
					%>
					</a></li>
					<li class="bread"><a href="">Dashboard > Product Management > Product List > <%
					if (action.equalsIgnoreCase("save")) {
					%>
						<td class="PageHeader">Product Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Product Update</td>
					<%
					}
					%></a></li>
				</ul>
			</div>
			<br>
		<div class="card">
			<div class="form-style-2">
<%
//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
Date date = new Date();  
String strDate = formatter.format(date);

/* String selectedProductTypeId = (String) request.getAttribute("selectedProductTypeId");
String selectedBrandId = (String) request.getAttribute("selectedBrandId");
String selectedProductCategoryId = (String) request.getAttribute("selectedProductCategoryId");
String selectedGenericId = (String) request.getAttribute("selectedGenericId");
String selectedPackPicecesId = (String) request.getAttribute("selectedPackPicecesId"); */
%>	
	<form action="ProductController" method="post" name="frmSave">
		<div class="form-style-2-heading">Provide your information</div>
			<div class="square-44">
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field1"><span>Product ID <span class="required">*</span></span>
				<%-- <input type="text" class="input-field-60" name="product_id" id="product_id" value="${product.product_id}"  maxlength=25 size=40 required /> --%>
				<!-- generated auto increment id during add [S] -->
				<input type="text" class="input-field-60" readonly="readonly" name="product_id" id="product_id" value="${productId}"  maxlength=25 size=40 required />
				<!-- generated auto increment id during add [E] --> 
			</label> 
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field1"><span>Product ID <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="product_id" id="product_id" value="${product.product_id}"  maxlength=25 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<label for="field2"><span>Product Name <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="product_name" id="product_name" value="${product.product_name}"  maxlength=100 size=40 required /> 
			</label>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field3"><span>Product Type ID </span>
				<select name="product_type_id" id="product_type_id" class="select-field-60" onchange="productTypeChng();" >
					<option value="" >Select one</option>
					<c:forEach items="${allProductType}" var="apt">
						<option value="${apt.product_type_id}">${apt.product_type_id}  -  ${apt.product_type}  -  ${apt.stength}</option>
					</c:forEach>
				</select> 
			</label>
			
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field3"><span>Product Type ID </span>
				<select name="product_type_id" id="product_type_id" class="select-field-60" onchange="productTypeChng();" >
					<%-- <option value="${product.product_type_id}" selected>${product.product_type_id}</option> --%>
					<c:forEach items="${allProductType}" var="apt">
						<option value="${apt.product_type_id}" ${apt.product_type_id == selectedProductTypeId ? 'selected="selected"' : ''}>${apt.product_type_id}  -  ${apt.product_type}  -  ${apt.stength}</option>
					</c:forEach>
				</select>
			</label>
			<%
			}
			%>
			
			<label for="field4"><span>Product Type <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="product_type" id="product_type" value="${product.product_type}"  maxlength=40 size=40 required /> 
			</label>
			
			<label for="field5"><span>Stength <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="stength" id="stength" value="${product.stength}"  maxlength=40 size=40 required /> 
			</label>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field6"><span>Brand ID </span>
				<select name="brand_id" id="brand_id" class="select-field-60" onchange="brandChng(); brandToProduct();" >
					<option value="" >Select one</option>
					<c:forEach items="${allBrand}" var="ab">
						<option value="${ab.brand_id}">${ab.brand_id}  -  ${ab.brand_name}</option>
					</c:forEach>
				</select> 
			</label>
			
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field6"><span>Brand ID </span>
				<select name="brand_id" id="brand_id" class="select-field-60" onchange="brandChng(); brandToProduct();" >
					<%-- <option value="${product.brand_id}" selected>${product.brand_id}</option> --%>
					<c:forEach items="${allBrand}" var="ab">
						<option value="${ab.brand_id}" ${ab.brand_id == selectedBrandId ? 'selected="selected"' : ''}>${ab.brand_id}  -  ${ab.brand_name}</option>
					</c:forEach>
				</select>
			</label>
			<%
			}
			%>
			
			<label for="field7"><span>Brand Name <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="brand_name" id="brand_name" value="${product.brand_name}" maxlength=100 size=40 required /> 
			</label>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field26"><span>Company ID </span>
				<select name="company_id" id="company_id" class="select-field-60" onchange="companyChng();" >
					<option value="" >Select one</option>
					<c:forEach items="${allCompany}" var="ac">
						<option value="${ac.company_id}">${ac.company_id}  -  ${ac.company_name}</option>
					</c:forEach>
				</select> 
			</label>
			
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field26"><span>Company ID </span>
				<select name="company_id" id="company_id" class="select-field-60" onchange="companyChng();" >
					<c:forEach items="${allCompany}" var="ac">
						<option value="${ac.company_id}" ${ac.company_id == selectedCompanyId ? 'selected="selected"' : ''}>${ac.company_id}  -  ${ac.company_name}</option>
					</c:forEach>
				</select>
			</label>
			<%
			}
			%>
			
			<label for="field27"><span>Company Name <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="company_name" id="company_name" value="${product.company_name}"  maxlength=100 size=40 required /> 
			</label>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field8"><span>Product Category ID </span>
				<select name="product_category_id" id="product_category_id" class="select-field-60" onchange="productCategoryChng();" >
					<option value="" >Select one</option>
					<c:forEach items="${allProductCategory}" var="apc">
						<option value="${apc.product_category_id}">${apc.product_category_id}  -  ${apc.product_category_name}</option>
					</c:forEach>
				</select> 
			</label>
			
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field8"><span>Product Category ID </span>
				<select name="product_category_id" id="product_category_id" class="select-field-60" onchange="productCategoryChng();" >
					<%-- <option value="${product.product_category_id}" selected>${product.product_category_id}</option> --%>
					<c:forEach items="${allProductCategory}" var="apc">
						<option value="${apc.product_category_id}" ${apc.product_category_id == selectedProductCategoryId ? 'selected="selected"' : ''}>${apc.product_category_id}  -  ${apc.product_category_name}</option>
					</c:forEach>
				</select>
			</label>
			<%
			}
			%>
			
			<label for="field9"><span>Product Category Name <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="product_category_name" id="product_category_name" value="${product.product_category_name}"  maxlength=100 size=40 required /> 
			</label>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field10"><span>Generic ID </span>
				<select name="generic_id" id="generic_id" class="select-field-60" onchange="genericChng();" >
					<option value="" >Select one</option>
					<c:forEach items="${allGeneric}" var="ag">
						<option value="${ag.generic_id}">${ag.generic_id}  -  ${ag.generic_name}</option>
					</c:forEach>
				</select> 
			</label>
			
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field10"><span>Generic ID </span>
				<select name="generic_id" id="generic_id" class="select-field-60" onchange="genericChng();" >
					<%-- <option value="${product.generic_id}" selected>${product.generic_id}</option> --%>
					<c:forEach items="${allGeneric}" var="ag">
						<option value="${ag.generic_id}" ${ag.generic_id == selectedGenericId ? 'selected="selected"' : ''}>${ag.generic_id}  -  ${ag.generic_name}</option>
					</c:forEach>
				</select>
			</label>
			<%
			}
			%>
			
			<label for="field11"><span>Generic Name <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="generic_name" id="generic_name" value="${product.generic_name}"  maxlength=100 size=40 required /> 
			</label>
			
			</div>
			
			&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
			
			<div class="square-44">
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field12"><span>Pack Pieces ID </span>
				<select name="pack_piceces_id" id="pack_piceces_id" class="select-field-60" onchange="packChng();" >
					<option value="" >Select one</option>
					<c:forEach items="${allPackPieces}" var="app">
						<option value="${app.pack_piceces_id}">${app.pack_piceces_id}  -  ${app.pack_type}  -  ${app.pack_size}  -  ${app.piceces}</option>
					</c:forEach>
				</select> 
			</label>
			
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field12"><span>Pack Pieces ID </span>
				<select name="pack_piceces_id" id="pack_piceces_id" class="select-field-60" onchange="packChng();" >
					<%-- <option value="${product.pack_piceces_id}" selected>${product.pack_piceces_id}</option> --%>
					<c:forEach items="${allPackPieces}" var="app">
						<option value="${app.pack_piceces_id}" ${app.pack_piceces_id == selectedPackPicecesId ? 'selected="selected"' : ''}>${app.pack_piceces_id}  -  ${app.pack_type}  -  ${app.pack_size}  -  ${app.piceces}</option>
					</c:forEach>
				</select>
			</label>
			<%
			}
			%>
			
			<label for="field13"><span>Pack Type <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="pack_type" id="pack_type" value="${product.pack_type}"  maxlength=40 size=40 required /> 
			</label>
			
			<label for="field14"><span>Pack Size </span>
				<input type="text" class="input-field-60" readonly="readonly" name="pack_size" id="pack_size" value="${product.pack_size}"  maxlength=25 size=40 /> 
			</label>
			
			<label for="field15"><span>Pieces </span>
				<input type="text" class="input-field-60" readonly="readonly" name="piceces" id="piceces" value="${product.piceces}"  maxlength=10 size=40 /> 
			</label>
			
			<label for="field16"><span>Rate Per Piece <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="rate_per_piceces" id="rate_per_piceces" value="${product.rate_per_piceces}" onchange="perPiecesToPerBox();"  maxlength=10 size=40 required /> 
			</label>
			
			<label for="field17"><span>Rate Per Box </span>
				<input type="text" class="input-field-60" name="rate_per_box" id="rate_per_box" value="${product.rate_per_box}" onchange="perBoxToPerPieces();" maxlength=10 size=40 /> 
			</label>
			
			<label for="field18"><span>TP </span>
				<input type="text" class="input-field-60" name="tp_price" id="tp_price" value="${product.tp_price}" onchange="tpPriceToTotalTpPrice();tpPriceToMrpPrice();totalTpPriceToTotalMrpPrice();" maxlength=10 size=40 /> 
			</label>
			
			<label for="field19"><span>MRP <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="mrp_price" id="mrp_price" value="${product.mrp_price}" onchange="mrpPriceToTotalMrpPrice();mrpPriceToTpPrice();tpPriceToTotalTpPrice();" maxlength=10 size=40 required /> 
			</label>
			
			<label for="field20"><span>Total TP </span>
				<input type="text" class="input-field-60" name="total_tp_price" id="total_tp_price" value="${product.total_tp_price}" onchange="totalTpPriceToTpPrice();tpPriceToMrpPrice();totalTpPriceToTotalMrpPrice();" maxlength=10 size=40 /> 
			</label>
			
			<label for="field21"><span>Total MRP </span>
				<input type="text" class="input-field-60" name="total_mrp_price" id="total_mrp_price" value="${product.total_mrp_price}" onchange="totalMrpPriceToMrpPrice();mrpPriceToTpPrice();tpPriceToTotalTpPrice();" maxlength=10 size=40 /> 
			</label>
			
			<label for="field22"><span>Stock <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="stock" id="stock" value="${product.stock}"  maxlength=25 size=40 required /> 
			</label>
			
			<label for="field23"><span>Bonus ID </span>
				<input type="text" class="input-field-60" name="bonus_id" id="bonus_id" value="${product.bonus_id}"  maxlength=25 size=40 /> 
			</label>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field124"><span>Created <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="<%=strDate%>" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="created" id="created" value="<%=strDate%>"  maxlength=14 size=40 required /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field124"><span>Created <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${product.created}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="created" id="created" value="${product.created}"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			</div>
			
			<div class="square-44">
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field125"><span>Updated </span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${product.updated}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="updated" id="updated" value="${product.updated}"  maxlength=14 size=40 /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field125"><span>Updated <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="<%=strDate%>" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="updated" id="updated" value="<%=strDate%>"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			</div>
			<br><br>
			<label><span></span>
					<input type="submit" value="Submit" />

					<a Class ="button" href="${pageContext.request.contextPath}/jsp/product/product.jsp">Return</a>
			</label>
			
	</form>
	</div>
		</div>	
	</div><!-- mcontent -->
	
</div><!-- main -->
</body>
</html>
<br>
<div>