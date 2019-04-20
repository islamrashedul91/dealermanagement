<jsp:include page="../../base.jsp"></jsp:include>
<br>
<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
	pageEncoding="ISO-8859-1"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<!-- <meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1"> -->
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet"
	href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/copytest.css" />
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/table.css" />

<script type="text/javascript"
	src="${pageContext.request.contextPath}/js/jquery.min.js"></script>
<script type="text/javascript"
	src="${pageContext.request.contextPath}/js/dataTables/jquery.dataTables.min.js"></script>
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/jquery.dataTables.min.css">
	
<title>onlinep</title>
<link rel="stylesheet" 	href="${pageContext.request.contextPath}/css/table.css">

<script type="text/javascript">

$(document).ready(function() {
	$('#example').DataTable();
});

function getRadioValue()
{
	var id = document.getElementsByName('purchase_product_id');
	var idValue;
	for(var i = 0; i < id.length; i++){
	    if(id[i].checked){
	    	idValue = id[i].value;
	    }
	}
	
	//for update [S]
	var updatePathWithIdValue = "${pageContext.request.contextPath}/PurchaseProductController?action=edit&purchase_product_id="+idValue;
	//for update [E]
	//for delete [S]
	var deletePathWithIdValue = "${pageContext.request.contextPath}/PurchaseProductController?action=delete&purchase_product_id="+idValue;
	//for delete [E]
	//for enquiry [S]
	var enquiryPathWithIdValue = "${pageContext.request.contextPath}/PurchaseProductController?action=enquiry&purchase_product_id="+idValue;
	//for enquiry [E]
	//for cancel [S]
	var cancelPathWithIdValue = "${pageContext.request.contextPath}/PurchaseProductController?action=cancel&purchase_product_id="+idValue;
	//for cancel [E]
	//for approve [S]
	var approvePathWithIdValue = "${pageContext.request.contextPath}/PurchaseProductController?action=approve&purchase_product_id="+idValue;
	//for approve [E]
	//for delivery return [S]
	var deliveryReturnPathWithIdValue = "${pageContext.request.contextPath}/PurchaseProductController?action=deliveryReturn&purchase_product_id="+idValue;
	//for delivery return [E]
	
	if (idValue !=null) {
		//for update [S]
		document.getElementById('update').href = updatePathWithIdValue;
		//for update [E]
		//for delete [S]
		document.getElementById('delete').href = deletePathWithIdValue;
		//for delete [E]
		//for enquiry [S]
		document.getElementById('enquiry').href = enquiryPathWithIdValue;
		//for enquiry [E]
		//for cancel [S]
		document.getElementById('cancel').href = cancelPathWithIdValue;
		//for cancel [E]
		//for approve [S]
		document.getElementById('approve').href = approvePathWithIdValue;
		//for approve [E]
		//for delivery return [S]
		document.getElementById('deliveryReturn').href = deliveryReturnPathWithIdValue;
		//for delivery return [E]
	} else {
		alert("Please select a ID !!");
		return false;
	}
}

</script>
</head>
<body>

<%
String message = (String) request.getAttribute("success");
%>
	<table align="center">
				<%
				if(message!=null) {
				%>
				<tr>
					<th Class="HeaderTH"><%=message %></th>
				</tr>
				<%
				}
				%>
	</table>
	<br>
<div class="mcontent">
			<div class="titlenav">
			<ul>
					<li class="title"><a href="${pageContext.request.contextPath}/jsp/order/salesProduct.jsp">Purchase Product List</a></li>
					<li class="bread"><a href="">Dashboard > Order 
							Management > Purchase List > Purchase Product List</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	<table class="display" style="width: 100%" cellspacing="10">			
		<tr>
			<td Class ="FormCellColor">Purchase ID</td>
			<td Class ="FormInputColor" colspan="2"><c:out value="${purchase_id}" /></td>
			<td Class ="FormCellColor">DateTime</td>
			<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${strDateTime}" /></td> --%>
			<td Class ="FormInputColor" colspan="2">
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${strDateTime}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
			</td>
			<td Class ="FormCellColor">Owner Name</td>
			<td Class ="FormInputColor" colspan="2"><c:out value="${owner_name}" /></td>
			<td Class ="FormCellColor">Mobile</td>
			<td Class ="FormInputColor" colspan="2"><c:out value="${mobile}" /></td>
			<td Class ="FormCellColor">Total Amount</td>
			<td Class ="FormInputColor" colspan="2"><c:out value="${sumTotalAmount}" /></td>
		</tr>
	</table>
</div>
			<br>
<div class="card">
	
	<table id="example" class="display" style="width: 100%; font-size: 13px;">
		<thead>
			<tr>
				<th  Class ="HeaderTH"></th>
				<th Class ="HeaderTH">Purchase Product ID</th>
				<th Class ="HeaderTH">DateTime</th>
				<!-- <th Class ="HeaderTH">Product ID</th> -->
				<th Class ="HeaderTH">Product Name</th>
				<!-- <th Class ="HeaderTH">Pack Type</th>
				<th Class ="HeaderTH">Pack Size</th>
				<th Class ="HeaderTH">Pieces</th>
				<th Class ="HeaderTH">Bonus ID</th>
				<th Class ="HeaderTH">Bonus Name</th> -->
				<!-- <th Class ="HeaderTH">Order Pack</th> -->
				<th Class ="HeaderTH">Order Quantity</th>
				<th Class ="HeaderTH">TP Price</th>
				<th Class ="HeaderTH">Total TP Price</th>
				<th Class ="HeaderTH">Discount Amount</th>
				<th Class ="HeaderTH">Total Amount</th>
				<th Class ="HeaderTH">Order Status</th>
				<th Class ="HeaderTH">Delivery Status</th>
			</tr>
		</thead>
		
		<tbody>
			<c:forEach items="${purchaseProducts}" var="pp"> 
				<tr>
					<td Class ="FormInputColor"><input type="radio" name="purchase_product_id" id="purchase_product_id" value="${pp.purchase_product_id}" onclick="javascript: getRadioValue();" /></td>
					<td Class ="FormInputColor"><c:out value="${pp.purchase_product_id}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${pp.date_time}" /></td> --%>
					<td Class ="FormInputColor">
						<fmt:parseDate pattern="yyyyMMddHHmmss" value="${pp.date_time}" var="parsedDate" />
						<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
					</td>
					<%-- <td Class ="FormInputColor"><c:out value="${pp.product_id}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${pp.product_name}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${pp.pack_type}" /></td>
					<td Class ="FormInputColor"><c:out value="${pp.pack_size}" /></td>
					<td Class ="FormInputColor"><c:out value="${pp.piceces}" /></td>
					<td Class ="FormInputColor"><c:out value="${pp.bonus_id}" /></td>
					<td Class ="FormInputColor"><c:out value="${pp.bonus_name}" /></td> --%>
					<%-- <td Class ="FormInputColor"><c:out value="${pp.order_pack}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${pp.order_quantity}" /></td>
					<td Class ="FormInputColor"><c:out value="${pp.tp_price}" /> <br>Unit Price</td>
					<td Class ="FormInputColor"><c:out value="${pp.total_tp_price}" /></td>
					<td Class ="FormInputColor"><c:out value="${pp.discount_amt}" /></td>
					<td Class ="FormInputColor"><c:out value="${pp.total_amount}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${pp.order_status}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${pp.order_status == 'P' ? 'Pending' : pp.order_status == 'A' ? 'Approved' : pp.order_status == 'C' ? 'Cancel' : pp.order_status == 'S' ? 'Success' : ''}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${pp.delivery_status}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${pp.delivery_status == 'P' ? 'Pending' : pp.delivery_status == 'D' ? 'Delivered' : pp.delivery_status == 'C' ? 'Cancel' : pp.delivery_status == 'S' ? 'Success' : pp.delivery_status == 'R' ? 'Return' : ''}" /></td>
				</tr>
			</c:forEach>
		</tbody>
	</table>
	<!-- for get Data from Purchase Main [S] -->
	<input type="hidden" name="purchase_id" id="purchase_id" value="${purchase_id}">
	<input type="hidden" name="purchase_type" id="purchase_type" value="${purchase_type}">
	<input type="hidden" name="strDateTime" id="strDateTime" value="${strDateTime}">
	<input type="hidden" name="owner_name" id="owner_name" value="${owner_name}">
	<input type="hidden" name="mobile" id="mobile" value="${mobile}">
	<%
	String purchase_id = (String)request.getAttribute("purchase_id");
	String purchase_type = (String)request.getAttribute("purchase_type");
	String strDateTime = (String)request.getAttribute("strDateTime");
	String owner_name = (String)request.getAttribute("owner_name");
	String mobile = (String)request.getAttribute("mobile");
	
	HttpSession session1 = request.getSession();
	session1.setAttribute("purchase_id", purchase_id);
	session1.setAttribute("purchase_type", purchase_type);
	session1.setAttribute("strDateTime", strDateTime);
	session1.setAttribute("owner_name", owner_name);
	session1.setAttribute("mobile", mobile);
	%>
	<!-- for get Data from Purchase Main [E] -->
	<br>
<input type="hidden" name="val" id="val" value="" />
	<table align="center" width="100%">
			
				<tr>
					<td><hr align=left width="100%" color=#003399>
					<br>
					<a Class ="button" href="${pageContext.request.contextPath}/PurchaseProductController?action=save">add</a>
					<a id="update" Class ="button" href="" onclick="javascript: getRadioValue();">update</a>
					<a id="approve" Class ="button" href="" onclick="javascript: getRadioValue();">approve</a>
					<a id="cancel" Class ="button" href="" onclick="javascript: getRadioValue();">cancel</a>
					<a id="delete" Class ="button" href="" onclick="javascript: getRadioValue();">delete</a>
					<a id="enquiry" Class ="button" href="" onclick="javascript: getRadioValue();">enquiry</a>
					<a id="deliveryReturn" Class ="button" href="" onclick="javascript: getRadioValue();">Delivery Return</a>
					<%-- <a Class ="button" href="${pageContext.request.contextPath}/PurchaseMainController?action=purchaseMainList&purchase_id=${purchase_id}&owner_name=${owner_name}&mobile=${mobile}">Return</a></td> --%>
					<a Class ="button" href="${pageContext.request.contextPath}/jsp/order/purchaseMain.jsp">Return</a></td>
				</tr>
	</table>
	</div>
</div><!-- mcontent -->
	
</div><!-- main -->
	
</body>
</html>