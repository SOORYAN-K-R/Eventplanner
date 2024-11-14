from app import app, db, Event, RSVP  

def delete_event(event_name):
    event_to_delete = Event.query.filter_by(name=event_name).first()
    if event_to_delete:
        RSVP.query.filter_by(event_id=event_to_delete.id).delete()
        db.session.delete(event_to_delete)
        db.session.commit()
        print(f"Event '{event_name}' and associated RSVPs deleted successfully.")
    else:
        print(f"Event '{event_name}' not found.")


with app.app_context():
    delete_event('farewell')
