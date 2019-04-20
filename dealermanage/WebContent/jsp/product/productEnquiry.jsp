<jsp:include page="../../base.jsp"></jsp:include>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<!DOCTYPE html>
<html>
<head>
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

		<div class="mcontent">
			<div class="titlenav">
				<ul>
					<li class="title"><a href="">Product Enquiry</a></li>
					<li class="bread"><a href="">Dashboard > Product
							Management > Product List > Product Enquiry</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	
	<form action="" method="post">
		<table id="example" class="display" style="width: 100%" cellspacing="10">			
			<tr>
				<td Class ="FormCellColor" colspan="2">Product ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${product.product_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Product Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${product.product_name}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Product Type ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${product.product_type_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Product Type</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${product.product_type}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Stength</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${product.stength}" /></td>
				<td Class ="FormCellColor" colspan="2"></td>
				<td Class ="FormInputColor" colspan="2"></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Brand ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${product.brand_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Brand Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${product.brand_name}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Company ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${product.company_id}" /></td>			
				<td Class ="FormCellColor" colspan="2">Company Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${product.company_name}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Product Category ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${product.product_category_id}" /></td>			
				<td Class ="FormCellColor" colspan="2">Product Category Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${product.product_category_name}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Generic ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${product.generic_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Generic Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${product.generic_name}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Pack Pieces ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${product.pack_piceces_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Pack Type</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${product.pack_type}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Pack Size</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${product.pack_size}" /></td>
				<td Class ="FormCellColor" colspan="2">Pieces</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${product.piceces}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Rate Per Piece</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${product.rate_per_piceces}" /></td>			
				<td Class ="FormCellColor" colspan="2">Rate Per Box</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${product.rate_per_box}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">TP</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${product.tp_price}" /></td>
				<td Class ="FormCellColor" colspan="2">MRP</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${product.mrp_price}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Total TP</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${product.total_tp_price}" /></td>
				<td Class ="FormCellColor" colspan="2">Total MRP</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${product.total_mrp_price}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Stock</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${product.stock}" /></td>
				<td Class ="FormCellColor" colspan="2">Bonus ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${product.bonus_id}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Created</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${product.created}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${product.created}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
				<td Class ="FormCellColor" colspan="2">Updated</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${product.updated}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${product.updated}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
			</tr>
		</table>
		<br>
		
		<table align="center" width="100%">
			
				<tr>
					<td><hr align=left width="100%" color=#003399><br>
						<a Class ="button" href="${pageContext.request.contextPath}/jsp/product/product.jsp">Return</a>
					</td>
				</tr>
		</table>
	</form>
	</div>
</div><!-- mcontent -->
	
</div><!-- main -->

	<!-- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ -->

</body>
</html>