from datetime import datetime

def global_site_data(request):

    """

    Context processor to inject global data into templates.

    """

    return {

    'current_year': datetime.now().year,

    }