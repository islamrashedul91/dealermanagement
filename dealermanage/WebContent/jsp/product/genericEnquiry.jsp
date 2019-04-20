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
					<li class="title"><a href="">Generic Enquiry</a></li>
					<li class="bread"><a href="">Dashboard > Product
							Management > Generic List > Generic Enquiry</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	
	<form action="" method="post">
		<table id="example" class="display" style="width: 100%" cellspacing="10">			
			<tr>
				<td Class ="FormCellColor" colspan="2">Generic ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${generic.generic_id}" /></td>			
				<td Class ="FormCellColor" colspan="2">Generic Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${generic.generic_name}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Product Category ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${generic.product_category_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Indications</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${generic.indications}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Adult Dose</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${generic.adult_dose}" /></td>			
				<td Class ="FormCellColor" colspan="2">Child Dose</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${generic.child_dose}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Renal Dose</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${generic.renal_dose}" /></td>
				<td Class ="FormCellColor" colspan="2">Administrations</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${generic.administrations}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Contraindications</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${generic.contraindications}" /></td>			
				<td Class ="FormCellColor" colspan="2">Side Effects</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${generic.side_effects}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Precautions Warnings</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${generic.precautions_warnings}" /></td>
				<td Class ="FormCellColor" colspan="2">Pregnancy Category</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${generic.pregnancy_category}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Therapeutic Class</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${generic.therapeutic_class}" /></td>			
				<td Class ="FormCellColor" colspan="2">Mode of Action</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${generic.mode_of_action}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Interaction</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${generic.interaction}" /></td>
				<td Class ="FormCellColor" colspan="2">Created</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${generic.created}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${generic.created}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Updated</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${generic.updated}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${generic.updated}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
			</tr>
		</table>
		<br>
		
		<table align="center" width="100%">
			
				<tr>
					<td><hr align=left width="100%" color=#003399><br>
						<a Class ="button" href="${pageContext.request.contextPath}/jsp/product/generic.jsp">Return</a>
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